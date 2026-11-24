//! Running as a Windows service (7.3.3): the Service Control Manager starts the process, which has to say within a few seconds
//! that it is starting, then running, and answer stop and shutdown. `RackhandProbe` runs as `NT SERVICE\RackhandProbe` and
//! `RackhandHelper` as SYSTEM; each is this binary with `service probe` or `service helper`.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use tokio::sync::Notify;
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_SHUTDOWN,
    SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STOP_PENDING,
    SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
};

/// What a service does: runs until told to stop, then returns.
pub type Body = fn(Arc<Notify>) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>>;

static BODY: OnceLock<(Vec<u16>, Body)> = OnceLock::new();
static STOP: OnceLock<Arc<Notify>> = OnceLock::new();
static HANDLE: AtomicUsize = AtomicUsize::new(0);
static CHECKPOINT: AtomicU32 = AtomicU32::new(0);

const NO_ERROR: u32 = 0;
/// How long a start or a stop may take before the manager gives up on it, in milliseconds.
const WAIT_HINT: u32 = 30_000;

fn report(state: u32, exit_code: u32) {
    let pending = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING;
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if pending { 0 } else { SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN },
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: if pending { CHECKPOINT.fetch_add(1, Ordering::Relaxed) + 1 } else { 0 },
        dwWaitHint: if pending { WAIT_HINT } else { 0 },
    };
    let handle = HANDLE.load(Ordering::Relaxed) as *mut c_void;
    // SAFETY: the handle came from RegisterServiceCtrlHandlerExW and `status` lives through the call
    unsafe { SetServiceStatus(handle, &status) };
}

unsafe extern "system" fn control(code: u32, _event: u32, _data: *mut c_void, _context: *mut c_void) -> u32 {
    if code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN {
        report(SERVICE_STOP_PENDING, NO_ERROR);
        if let Some(stop) = STOP.get() {
            stop.notify_one();
        }
    }
    NO_ERROR
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let Some((name, body)) = BODY.get() else { return };
    // SAFETY: `name` is NUL-terminated and lives for the program
    let handle = unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control), std::ptr::null()) };
    if handle.is_null() {
        return;
    }
    HANDLE.store(handle as usize, Ordering::Relaxed);
    report(SERVICE_START_PENDING, NO_ERROR);
    let stop = Arc::new(Notify::new());
    let _ = STOP.set(stop.clone());
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(r) => r,
        Err(_) => {
            report(SERVICE_STOPPED, 1);
            return;
        }
    };
    report(SERVICE_RUNNING, NO_ERROR);
    let result = runtime.block_on(body(stop));
    report(SERVICE_STOPPED, u32::from(result.is_err()));
}

/// Hands this process to the Service Control Manager as the service `name` running `body`. It returns when the service has
/// stopped, or at once with an error when the process wasn't started by the manager.
pub fn dispatch(name: &str, body: Body) -> Result<(), String> {
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    BODY.set((wide, body)).map_err(|_| "a service is already running in this process".to_string())?;
    let (name, _) = BODY.get().ok_or("no service")?;
    let table = [
        SERVICE_TABLE_ENTRYW { lpServiceName: name.as_ptr().cast_mut(), lpServiceProc: Some(service_main) },
        SERVICE_TABLE_ENTRYW { lpServiceName: std::ptr::null_mut(), lpServiceProc: None },
    ];
    // SAFETY: the table ends with a null entry and the names live for the program
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(format!("not started by the service manager: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}
