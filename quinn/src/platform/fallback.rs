use mio::net::UdpSocket;

use quinn_proto::EcnCodepoint;

pub fn init(socket: &UdpSocket) -> io::Result<()> {}

pub fn send(
    socket: &UdpSocket,
    remote: &SocketAddr,
    ecn: Option<EcnCodepoint>,
    msg: &[u8],
) -> io::Result<usize> {
    socket.send_to(msg, remote)
}

pub fn recv(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<EcnCodepoint>)> {
    socket.recv_from(buf).map(|(x, y)| (x, y, None))
}
