use std::{io, net::SocketAddr};

use tokio::net::{TcpListener, TcpSocket};

pub(crate) fn bind_local_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = match addr {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    #[cfg(not(windows))]
    socket.set_reuseaddr(true)?;
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            SO_EXCLUSIVEADDRUSE, SOCKET_ERROR, SOL_SOCKET, WSAGetLastError, setsockopt,
        };

        let enabled = 1_i32;
        // SAFETY: the socket is open and Winsock reads a BOOL from enabled during the call.
        let result = unsafe {
            setsockopt(
                socket.as_raw_socket() as usize,
                SOL_SOCKET,
                SO_EXCLUSIVEADDRUSE,
                (&raw const enabled).cast(),
                size_of::<i32>() as i32,
            )
        };
        if result == SOCKET_ERROR {
            return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
        }
    }
    socket.bind(addr).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("Local proxy could not listen on {addr}: {err}"),
        )
    })?;
    socket.listen(4096)
}

#[cfg(all(test, windows))]
#[tokio::test]
async fn rejects_another_process_configuration_on_the_same_port() {
    let first = bind_local_listener("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = first.local_addr().unwrap();
    let second = bind_local_listener(addr).unwrap_err();
    assert!(second.to_string().contains(&addr.to_string()));
    let legacy = TcpSocket::new_v4().unwrap();
    legacy.set_reuseaddr(true).unwrap();
    assert!(legacy.bind(addr).is_err());

    let legacy = TcpSocket::new_v4().unwrap();
    legacy.set_reuseaddr(true).unwrap();
    legacy.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let legacy = legacy.listen(128).unwrap();
    assert!(bind_local_listener(legacy.local_addr().unwrap()).is_err());
}
