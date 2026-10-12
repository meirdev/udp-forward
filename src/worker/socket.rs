//! Socket helpers shared by sources and sinks.

use std::io;
use std::os::fd::AsRawFd;

use socket2::{Domain, Socket};

/// The socket domain for an address family.
pub(crate) fn domain_for(is_ipv6: bool) -> Domain {
    if is_ipv6 { Domain::IPV6 } else { Domain::IPV4 }
}

/// Sets a socket option that socket2 does not expose, passing `value` by
/// pointer and size.
pub(crate) fn set_raw_option<T>(
    socket: &Socket,
    level: libc::c_int,
    name: libc::c_int,
    value: &T,
) -> io::Result<()> {
    // SAFETY: value is a live T, and the kernel reads exactly size_of::<T>()
    // bytes from it during the call.
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            name,
            value as *const T as *const libc::c_void,
            std::mem::size_of::<T>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
