use std::io;
use std::net::SocketAddr;

use futures::{try_ready, Async, Poll};
use mio;

use tokio_reactor::{Handle, PollEvented};

use quinn_proto::EcnCodepoint;

use crate::platform;

/// Tokio-compatible UDP socket with some useful specializations.
///
/// Unlike a standard tokio UDP socket, this allows ECN bits to be read and written on some
/// platforms.
pub struct UdpSocket {
    io: PollEvented<mio::net::UdpSocket>,
}

impl UdpSocket {
    pub fn from_std(socket: std::net::UdpSocket, handle: &Handle) -> io::Result<UdpSocket> {
        let io = mio::net::UdpSocket::from_socket(socket)?;
        platform::init(&io)?;
        let io = PollEvented::new_with_handle(io, handle)?;
        Ok(UdpSocket { io })
    }

    pub fn poll_send(
        &self,
        remote: &SocketAddr,
        ecn: Option<EcnCodepoint>,
        msg: &[u8],
    ) -> Poll<usize, io::Error> {
        try_ready!(self.io.poll_write_ready());
        match platform::send(self.io.get_ref(), remote, ecn, msg) {
            Ok(n) => Ok(Async::Ready(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.io.clear_write_ready()?;
                Ok(Async::NotReady)
            }
            Err(e) => Err(e),
        }
    }

    pub fn poll_recv(
        &self,
        buf: &mut [u8],
    ) -> Poll<(usize, SocketAddr, Option<EcnCodepoint>), io::Error> {
        try_ready!(self.io.poll_read_ready(mio::Ready::readable()));
        match platform::recv(self.io.get_ref(), buf) {
            Ok(n) => Ok(n.into()),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                self.io.clear_read_ready(mio::Ready::readable())?;
                Ok(Async::NotReady)
            }
            Err(e) => Err(e),
        }
    }
}
