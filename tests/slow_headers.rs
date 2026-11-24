//! The HTTP server loop (`serve_until`): request headers have a deadline, so a client cannot
//! hold a socket open by sending them byte by byte (slowloris).

mod common;

use std::time::{Duration, Instant};

use common::*;
use hangar_server::config::{Config, IdentityMode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn serve() -> (std::net::SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let config = Config::for_tests(IdentityMode::Official, website_keys());
    let server = hangar_server::build(config).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(hangar_server::serve_until(server, listener, async {
        let _ = stop_rx.await;
    }));
    (addr, stop_tx)
}

#[tokio::test]
async fn incomplete_request_headers_are_cut_off() {
    let (addr, _stop) = serve().await;
    let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    socket
        .write_all(b"GET /health HTTP/1.1\r\nHost: x\r\n")
        .await
        .unwrap();
    let started = Instant::now();
    let mut buffer = [0u8; 256];
    // Whatever the server answers (408 or nothing), it closes the socket in the end.
    let closed = tokio::time::timeout(
        hangar_server::HEADER_READ_TIMEOUT + Duration::from_secs(5),
        async {
            loop {
                match socket.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => continue,
                }
            }
        },
    )
    .await;
    assert!(closed.is_ok(), "socket still open after the deadline");
    assert!(
        started.elapsed() >= hangar_server::HEADER_READ_TIMEOUT - Duration::from_secs(1),
        "closed before the deadline: {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn silent_sockets_are_cut_off() {
    let (addr, _stop) = serve().await;
    // Connects and never sends a byte: the same deadline applies.
    let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut buffer = [0u8; 256];
    let closed = tokio::time::timeout(
        hangar_server::HEADER_READ_TIMEOUT + Duration::from_secs(5),
        async {
            loop {
                match socket.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => continue,
                }
            }
        },
    )
    .await;
    assert!(
        closed.is_ok(),
        "silent socket still open after the deadline"
    );
}

#[tokio::test]
async fn complete_requests_are_answered() {
    let (addr, _stop) = serve().await;
    let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
    socket
        .write_all(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut answer = Vec::new();
    socket.read_to_end(&mut answer).await.unwrap();
    let answer = String::from_utf8_lossy(&answer);
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(answer.contains("\"status\":\"ok\""), "{answer}");
}
