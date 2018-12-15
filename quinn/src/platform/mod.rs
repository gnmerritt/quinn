//! Uniform interface to send/recv UDP packets with ECN information.

// The Linux code should work for most unixes, but as of this writing nobody's ported the
// CMSG_... macros to the libc crate for any of the BSDs.
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use self::linux::*;

// No ECN support
#[cfg(not(target_os = "linux"))]
mod fallback;
#[cfg(not(target_os = "linux"))]
pub use self::fallback::*;
