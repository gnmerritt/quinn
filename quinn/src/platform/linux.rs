use std::os::unix::io::AsRawFd;
use std::{
    io, mem,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    ptr,
};

use mio::net::UdpSocket;

use quinn_proto::EcnCodepoint;

const CMSG_LEN: usize = 24;

pub fn init(socket: &UdpSocket) -> io::Result<()> {
    // Safety
    assert_eq!(
        mem::size_of::<SocketAddrV4>(),
        mem::size_of::<libc::sockaddr_in>()
    );
    assert_eq!(
        mem::size_of::<SocketAddrV6>(),
        mem::size_of::<libc::sockaddr_in6>()
    );
    assert_eq!(
        CMSG_LEN,
        std::cmp::max(
            unsafe { libc::CMSG_SPACE(mem::size_of::<libc::c_int>() as _) },
            unsafe { libc::CMSG_SPACE(1) }
        ) as usize
    );

    if !socket.only_v6()? {
        let rc = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IP,
                libc::IP_RECVTOS,
                &true as *const _ as _,
                1,
            )
        };
        if rc == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    let on: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVTCLASS,
            &on as *const _ as _,
            mem::size_of::<libc::c_int>() as _,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn send(
    socket: &UdpSocket,
    remote: &SocketAddr,
    ecn: Option<EcnCodepoint>,
    msg: &[u8],
) -> io::Result<usize> {
    let (name, namelen) = match *remote {
        SocketAddr::V4(ref addr) => (addr as *const _ as _, mem::size_of::<libc::sockaddr_in>()),
        SocketAddr::V6(ref addr) => (addr as *const _ as _, mem::size_of::<libc::sockaddr_in6>()),
    };
    let ecn = ecn.map_or(0, |x| x as u8);
    let mut iov = libc::iovec {
        iov_base: msg.as_ptr() as *const _ as *mut _,
        iov_len: msg.len(),
    };
    let mut ctrl: [u8; CMSG_LEN] = unsafe { mem::uninitialized() };
    let mut hdr = libc::msghdr {
        msg_name: name,
        msg_namelen: namelen as _,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: ctrl.as_mut_ptr() as _,
        msg_controllen: CMSG_LEN as _,
        msg_flags: 0,
    };
    hdr.msg_controllen = if remote.is_ipv4() {
        unsafe {
            let cmsg = &mut *libc::CMSG_FIRSTHDR(&hdr);
            cmsg.cmsg_level = libc::IPPROTO_IP;
            cmsg.cmsg_type = libc::IP_TOS;
            cmsg.cmsg_len = libc::CMSG_LEN(1) as _;
            *libc::CMSG_DATA(cmsg) = ecn as libc::c_uchar;
            libc::CMSG_SPACE(1) as _
        }
    } else {
        unsafe {
            let cmsg = &mut *libc::CMSG_FIRSTHDR(&hdr);
            cmsg.cmsg_level = libc::IPPROTO_IPV6;
            cmsg.cmsg_type = libc::IPV6_TCLASS;
            cmsg.cmsg_len = libc::CMSG_LEN(mem::size_of::<libc::c_int>() as _) as _;
            *(libc::CMSG_DATA(cmsg) as *mut libc::c_int) = ecn as _;
            libc::CMSG_SPACE(mem::size_of::<libc::c_int>() as _) as _
        }
    };
    let n = unsafe { libc::sendmsg(socket.as_raw_fd(), &hdr, 0) };
    if n == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

pub fn recv(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<EcnCodepoint>)> {
    let mut name: libc::sockaddr_storage = unsafe { mem::uninitialized() };
    let mut iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut _,
        iov_len: buf.len(),
    };
    let mut ctrl: [u8; CMSG_LEN] = unsafe { mem::uninitialized() };
    let mut hdr = libc::msghdr {
        msg_name: &mut name as *mut _ as _,
        msg_namelen: mem::size_of::<libc::sockaddr_storage>() as _,
        msg_iov: &mut iov,
        msg_iovlen: 1,
        msg_control: ctrl.as_mut_ptr() as _,
        msg_controllen: CMSG_LEN as _,
        msg_flags: 0,
    };
    let n = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut hdr, 0) };
    if n == -1 {
        return Err(io::Error::last_os_error());
    }
    let mut ecn = None;
    let addr = match name.ss_family as libc::c_int {
        libc::AF_INET => unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&hdr);
            loop {
                if cmsg.is_null() {
                    break;
                }
                let c = &*cmsg;
                if c.cmsg_level == libc::IPPROTO_IP && c.cmsg_type == libc::IP_TOS {
                    ecn = EcnCodepoint::from_bits(*libc::CMSG_DATA(c) as u8);
                }
                cmsg = libc::CMSG_NXTHDR(&hdr, c);
            }
            SocketAddr::V4(ptr::read(&name as *const _ as _))
        },
        libc::AF_INET6 => unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&hdr);
            loop {
                if cmsg.is_null() {
                    break;
                }
                let c = &*cmsg;
                if c.cmsg_level == libc::IPPROTO_IPV6 && c.cmsg_type == libc::IPV6_TCLASS {
                    ecn =
                        EcnCodepoint::from_bits(*(libc::CMSG_DATA(c) as *const libc::c_int) as u8);
                }
                cmsg = libc::CMSG_NXTHDR(&hdr, c);
            }
            SocketAddr::V6(ptr::read(&name as *const _ as _))
        },
        _ => unreachable!(),
    };
    Ok((n as usize, addr, ecn))
}
