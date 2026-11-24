//! The helper's side of the named pipe (7.3.3): `\\.\pipe\rackhand-helper`, created with the security descriptor of
//! [`super::parse::pipe::sddl`] so that only SYSTEM and `NT SERVICE\RackhandProbe` can open it, and with remote clients
//! refused. One JSON request per line and one response per line, as on Linux; a line longer than the limit closes the
//! connection.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::sync::Arc;

use rackhand_proto::helper::{HelperRequest, HelperResponse, parse_request};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

use super::helper_ops;
use super::parse::pipe::{PROBE_SERVICE, sddl};
use crate::helper::server::{Helper, MAX_LINE};

/// A security descriptor made from SDDL, freed when dropped.
struct Descriptor(*mut c_void);

// SAFETY: the descriptor is read-only memory that nothing else frees, used from one task at a time
unsafe impl Send for Descriptor {}

impl Descriptor {
    fn from_sddl(text: &str) -> io::Result<Descriptor> {
        let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sd: *mut c_void = std::ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated and outlives the call; `sd` receives memory that `Drop` frees
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(Descriptor(sd)) }
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: the pointer came from the conversion above and is freed once
        unsafe { LocalFree(self.0) };
    }
}

/// One instance of the pipe, ready for a client.
fn create(path: &str, first: bool) -> io::Result<NamedPipeServer> {
    let descriptor = Descriptor::from_sddl(&sddl(PROBE_SERVICE))?;
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let mut options = ServerOptions::new();
    options.first_pipe_instance(first).reject_remote_clients(true);
    // SAFETY: `attrs` is a valid SECURITY_ATTRIBUTES whose descriptor lives until the call returns
    unsafe { options.create_with_security_attributes_raw(path, (&mut attrs as *mut SECURITY_ATTRIBUTES).cast()) }
}

fn error(code: &str, message: impl Into<String>) -> HelperResponse {
    HelperResponse::Error { code: code.into(), message: message.into() }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// The answer to one request line.
async fn answer(helper: &Helper, line: &str) -> HelperResponse {
    match parse_request(line) {
        Ok(HelperRequest::SocketOwners { inodes }) => {
            if inodes.len() > 4096 {
                return error("too_many", "too many sockets in one request");
            }
            match helper_ops::socket_owners(&inodes).await {
                Ok(owners) => HelperResponse::SocketOwners { owners },
                Err(e) => error("owners_unavailable", e),
            }
        }
        Ok(HelperRequest::ProcessScan) => match helper_ops::process_scan().await {
            Ok(items) => HelperResponse::Processes { items },
            Err(e) => error("processes_unavailable", e),
        },
        Ok(HelperRequest::AuthEventsSince { cursor }) => {
            match helper_ops::auth_since(cursor.as_deref(), now_ms()).await {
                Ok((events, cursor)) => HelperResponse::AuthEvents { events, cursor },
                Err(e) => error("auth_unavailable", e),
            }
        }
        _ => helper.answer(line),
    }
}

async fn connection(pipe: NamedPipeServer, helper: Arc<Helper>) {
    let (read, mut write) = tokio::io::split(pipe);
    let mut lines = BufReader::new(read);
    let mut line = String::new();
    loop {
        line.clear();
        match (&mut lines).take(MAX_LINE as u64 + 1).read_line(&mut line).await {
            Ok(0) | Err(_) => return,
            Ok(n) if n > MAX_LINE => return,
            Ok(_) => {}
        }
        let mut reply = match serde_json::to_string(&answer(&helper, line.trim_end()).await) {
            Ok(r) => r,
            Err(_) => return,
        };
        reply.push('\n');
        if write.write_all(reply.as_bytes()).await.is_err() {
            return;
        }
    }
}

/// Serves the pipe until the task is dropped: a new instance for each client.
pub async fn serve(path: &str, helper: Arc<Helper>) -> io::Result<()> {
    let mut server = create(path, true)?;
    loop {
        server.connect().await?;
        let connected = std::mem::replace(&mut server, create(path, false)?);
        let helper = helper.clone();
        tokio::spawn(async move { connection(connected, helper).await });
    }
}
