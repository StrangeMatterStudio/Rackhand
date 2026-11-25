// SPDX-License-Identifier: GPL-2.0 OR MIT
//! The probe's capture (design FR-4, FR-5, 11, D17, D103, D111): outbound TCP connects and UDP flows, and execs.
//!
//! - `cgroup/connect4`, `connect6`, `sendmsg4` and `sendmsg6` on the root cgroup count each
//!   `(cgroup, process, user, destination, port, protocol)` in a per-CPU LRU map that user space drains every interval.
//!   A connected UDP socket is seen once, at its `connect`; an IPv4 destination from an IPv6 socket arrives as a mapped
//!   address, which user space unmaps.
//! - The `sched/sched_process_exec` tracepoint keeps each process's executable path by pid, so the connection hooks'
//!   records name it even after the process exits, and sends each exec to user space through a ring buffer.
//!
//! The layouts below are mirrored by `rackhand-probe`'s `security::ebpf`, which tests their sizes.
#![no_std]
#![no_main]

use aya_ebpf::helpers::{
    bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
    bpf_probe_read_kernel_str_bytes,
};
use aya_ebpf::macros::{cgroup_sock_addr, map, tracepoint};
use aya_ebpf::maps::{LruHashMap, LruPerCpuHashMap, PerCpuArray, RingBuf};
use aya_ebpf::programs::{SockAddrContext, TracePointContext};

const PATH_LEN: usize = 256;
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

/// One counted connection. 48 bytes, no padding the kernel could leave unset.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnKey {
    pub cgroup: u64,
    /// The destination, IPv4 as `::ffff:a.b.c.d`, in network order.
    pub addr: [u8; 16],
    pub tgid: u32,
    pub uid: u32,
    /// The destination port, host order.
    pub port: u16,
    pub proto: u8,
    pub _pad: [u8; 5],
    pub comm: [u8; 8],
}

/// A process's executable path, NUL-terminated.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Exe {
    pub path: [u8; PATH_LEN],
}

/// One exec, sent to user space. 288 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub cgroup: u64,
    pub tgid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub path: [u8; PATH_LEN],
}

#[map]
static CONNS: LruPerCpuHashMap<ConnKey, u64> = LruPerCpuHashMap::with_max_entries(4096, 0);

#[map]
static EXES: LruHashMap<u32, Exe> = LruHashMap::with_max_entries(8192, 0);

#[map]
static EXECS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Scratch space for a path, too big for the eBPF stack.
#[map]
static SCRATCH: PerCpuArray<Exe> = PerCpuArray::with_max_entries(1, 0);

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    count(&ctx, ipv4(&ctx));
    1
}

#[cgroup_sock_addr(connect6)]
pub fn connect6(ctx: SockAddrContext) -> i32 {
    count(&ctx, ipv6(&ctx));
    1
}

#[cgroup_sock_addr(sendmsg4)]
pub fn sendmsg4(ctx: SockAddrContext) -> i32 {
    count(&ctx, ipv4(&ctx));
    1
}

#[cgroup_sock_addr(sendmsg6)]
pub fn sendmsg6(ctx: SockAddrContext) -> i32 {
    count(&ctx, ipv6(&ctx));
    1
}

// The verifier allows only direct loads from the context (no pointer moved first), and only the fields of the hook's
// own family: each read below is one volatile load of one field.

/// The destination of an IPv4 hook, as `::ffff:a.b.c.d`.
#[inline(always)]
fn ipv4(ctx: &SockAddrContext) -> [u8; 16] {
    // SAFETY: the kernel passes a valid `bpf_sock_addr`; `user_ip4` is readable in the IPv4 hooks.
    let ip = unsafe { core::ptr::read_volatile(&raw const (*ctx.sock_addr).user_ip4) };
    let mut addr = [0u8; 16];
    addr[10] = 0xff;
    addr[11] = 0xff;
    let b = ip.to_ne_bytes();
    addr[12] = b[0];
    addr[13] = b[1];
    addr[14] = b[2];
    addr[15] = b[3];
    addr
}

/// The destination of an IPv6 hook.
#[inline(always)]
fn ipv6(ctx: &SockAddrContext) -> [u8; 16] {
    // SAFETY: as above; `user_ip6` is readable in the IPv6 hooks, one 32-bit word at a time.
    let w = unsafe {
        [
            core::ptr::read_volatile(&raw const (*ctx.sock_addr).user_ip6[0]),
            core::ptr::read_volatile(&raw const (*ctx.sock_addr).user_ip6[1]),
            core::ptr::read_volatile(&raw const (*ctx.sock_addr).user_ip6[2]),
            core::ptr::read_volatile(&raw const (*ctx.sock_addr).user_ip6[3]),
        ]
    };
    let mut addr = [0u8; 16];
    let mut i = 0;
    while i < 4 {
        let b = w[i].to_ne_bytes();
        addr[i * 4] = b[0];
        addr[i * 4 + 1] = b[1];
        addr[i * 4 + 2] = b[2];
        addr[i * 4 + 3] = b[3];
        i += 1;
    }
    addr
}

#[inline(always)]
fn count(ctx: &SockAddrContext, addr: [u8; 16]) {
    // SAFETY: direct single-field loads from the context, as above.
    let (kind, port) = unsafe {
        (
            core::ptr::read_volatile(&raw const (*ctx.sock_addr).type_),
            core::ptr::read_volatile(&raw const (*ctx.sock_addr).user_port),
        )
    };
    let proto = match kind {
        SOCK_STREAM => PROTO_TCP,
        SOCK_DGRAM => PROTO_UDP,
        _ => return,
    };
    let port = u16::from_be(port as u16);
    let mut comm = [0u8; 8];
    if let Ok(c) = bpf_get_current_comm() {
        comm.copy_from_slice(&c[..8]);
    }
    let key = ConnKey {
        // SAFETY: plain helper calls with no arguments.
        cgroup: unsafe { bpf_get_current_cgroup_id() },
        addr,
        tgid: (bpf_get_current_pid_tgid() >> 32) as u32,
        uid: bpf_get_current_uid_gid() as u32,
        port,
        proto,
        _pad: [0; 5],
        comm,
    };
    match CONNS.get_ptr_mut(&key) {
        // SAFETY: a per-CPU value is only written from this CPU.
        Some(n) => unsafe { *n += 1 },
        None => {
            let _ = CONNS.insert(&key, &1, 0);
        }
    }
}

/// `sched_process_exec`: the `__data_loc` of the filename sits at offset 8 of the record on every kernel since 3.4.
#[tracepoint]
pub fn exec(ctx: TracePointContext) -> u32 {
    let _ = on_exec(&ctx);
    0
}

fn on_exec(ctx: &TracePointContext) -> Result<(), i32> {
    // SAFETY: offset 8 is inside the record, and `read_at` copies through the kernel's checked read.
    let loc: u32 = unsafe { ctx.read_at(8)? };
    let scratch = SCRATCH.get_ptr_mut(0).ok_or(0)?;
    // SAFETY: the per-CPU scratch slot is only used by this CPU, for the length of this call.
    let exe = unsafe { &mut *scratch };
    let filename = unsafe { (ctx.as_ptr_u8()).add((loc & 0xffff) as usize) };
    // SAFETY: `filename` points into the tracepoint record; the read is bounded by the buffer.
    unsafe { bpf_probe_read_kernel_str_bytes(filename, &mut exe.path)? };
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let _ = EXES.insert(&tgid, exe, 0);
    if let Some(mut entry) = EXECS.reserve::<ExecEvent>(0) {
        let event = entry.as_mut_ptr();
        // SAFETY: the reserved entry is ours until submitted.
        unsafe {
            (*event).cgroup = bpf_get_current_cgroup_id();
            (*event).tgid = tgid;
            (*event).uid = bpf_get_current_uid_gid() as u32;
            (*event).comm = bpf_get_current_comm().unwrap_or([0; 16]);
            (*event).path = exe.path;
        }
        entry.submit(0);
    }
    Ok(())
}

trait RecordPtr {
    fn as_ptr_u8(&self) -> *const u8;
}

impl RecordPtr for TracePointContext {
    fn as_ptr_u8(&self) -> *const u8 {
        use aya_ebpf::EbpfContext;
        self.as_ptr() as *const u8
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// The licence the kernel checks for GPL-only helpers (`bpf_probe_read_kernel`, D111).
#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
