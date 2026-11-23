//! Contract checks for native helper multiplexing.

use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use concurro_relay_native_transport::tunnel::{Frame, Kind, MAX_PAYLOAD, Role, Tunnel, WINDOW};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time,
};

/// Preserve the exact frame header and decode arbitrary fragmentation.
#[tokio::test]
async fn frame_wire_fragments_limits_and_eof() {
    let frame = Frame {
        kind: Kind::Data,
        channel: 7,
        payload: b"abc".to_vec(),
    };
    let (mut writer, mut reader) = tokio::io::duplex(32);
    frame.write(&mut writer).await.unwrap();
    let mut bytes = [0; 12];
    reader.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"D\0\0\0\x07\0\0\0\x03abc");
    let (mut writer, mut reader) = tokio::io::duplex(1);
    let sending = tokio::spawn(async move {
        for byte in bytes {
            writer.write_all(&[byte]).await.unwrap();
        }
    });
    assert_eq!(Frame::read(&mut reader).await.unwrap(), frame);
    sending.await.unwrap();

    let (mut writer, mut reader) = tokio::io::duplex(16);
    writer.write_all(b"D\0\0\0\x01\0\x01\0\x01").await.unwrap();
    assert!(
        Frame::read(&mut reader)
            .await
            .unwrap_err()
            .to_string()
            .contains("too large")
    );
    let too_large = Frame {
        kind: Kind::Data,
        channel: 1,
        payload: vec![0; MAX_PAYLOAD + 1],
    };
    assert!(too_large.write(&mut writer).await.is_err());
    let largest = Frame {
        kind: Kind::Data,
        channel: 1,
        payload: vec![b'z'; MAX_PAYLOAD],
    };
    let (mut writer, mut reader) = tokio::io::duplex(MAX_PAYLOAD + 9);
    largest.write(&mut writer).await.unwrap();
    assert_eq!(Frame::read(&mut reader).await.unwrap(), largest);
    let (mut writer, mut reader) = tokio::io::duplex(16);
    writer.write_all(b"D\0\0").await.unwrap();
    drop(writer);
    assert!(Frame::read(&mut reader).await.is_err());
}

/// Carry two independent large streams through one link and preserve EOF.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_channels_and_half_close() {
    time::timeout(Duration::from_secs(15), async {
        let (sponsor_link, concurro_link) = tokio::io::duplex(4096);
        let sponsor = Tunnel::start(sponsor_link, Role::Sponsor);
        let concurro = Tunnel::start(concurro_link, Role::Concurro);
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target = upstream.local_addr().unwrap().port();
        let registration = sponsor.register(target).await.unwrap();
        let mapped = registration.port();
        let claim = concurro.claim(mapped).unwrap();
        let upstream_task = tokio::spawn(async move {
            let mut tasks = Vec::new();
            for _ in 0..2 {
                let (mut socket, _) = upstream.accept().await.unwrap();
                tasks.push(tokio::spawn(async move {
                    let mut body = Vec::new();
                    socket.read_to_end(&mut body).await.unwrap();
                    socket.write_all(&body).await.unwrap();
                    socket.shutdown().await.unwrap();
                    body
                }));
            }
            let mut bodies = Vec::new();
            for task in tasks {
                bodies.push(task.await.unwrap());
            }
            bodies
        });
        let mut clients = Vec::new();
        let expected = [vec![b'a'; 150_000], vec![b'b'; 210_000]];
        for body in expected.clone() {
            clients.push(tokio::spawn(async move {
                let mut socket = TcpStream::connect((Ipv4Addr::LOCALHOST, mapped))
                    .await
                    .unwrap();
                socket.write_all(&body).await.unwrap();
                socket.shutdown().await.unwrap();
                let mut echoed = Vec::new();
                socket.read_to_end(&mut echoed).await.unwrap();
                (body, echoed)
            }));
        }
        for task in clients {
            let (sent, echoed) = task.await.unwrap();
            assert_eq!(sent, echoed);
        }
        let mut received = upstream_task.await.unwrap();
        received.sort();
        let mut expected = expected.to_vec();
        expected.sort();
        assert_eq!(received, expected);
        drop((claim, registration));
        sponsor.close();
        concurro.close();
    })
    .await
    .unwrap();
}

/// A slow or absent target must not stall an unrelated mapped channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delayed_target_does_not_block_other_channels() {
    time::timeout(Duration::from_secs(5), async {
        let (sponsor_link, concurro_link) = tokio::io::duplex(1024);
        let sponsor = Tunnel::start(sponsor_link, Role::Sponsor);
        let concurro = Tunnel::start(concurro_link, Role::Concurro);
        let reserved = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let absent = reserved.local_addr().unwrap().port();
        drop(reserved);
        let slow = sponsor.register(absent).await.unwrap();
        let _waiting = TcpStream::connect((Ipv4Addr::LOCALHOST, slow.port()))
            .await
            .unwrap();
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target = upstream.local_addr().unwrap().port();
        let fast = sponsor.register(target).await.unwrap();
        let echo = tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.unwrap();
            let mut bytes = [0; 3];
            socket.read_exact(&mut bytes).await.unwrap();
            socket.write_all(&bytes).await.unwrap();
        });
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, fast.port()))
            .await
            .unwrap();
        client.write_all(b"ok!").await.unwrap();
        let mut answer = [0; 3];
        client.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"ok!");
        echo.await.unwrap();
        sponsor.close();
        concurro.close();
    })
    .await
    .unwrap();
}

/// A cancelled tunnel hands out no listener.
#[tokio::test]
async fn cancellation_refuses_claims() {
    let (left, _right) = tokio::io::duplex(64);
    let tunnel = Tunnel::start(left, Role::Concurro);
    tunnel.cancel();
    assert!(
        tunnel
            .claim(12345)
            .unwrap_err()
            .to_string()
            .contains("closed")
    );
}

/// A large transfer to a helper that reads slowly arrives whole, within the
/// channel's window.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_reader_receives_everything() {
    time::timeout(Duration::from_secs(20), async {
        let (sponsor_link, concurro_link) = tokio::io::duplex(1 << 16);
        let sponsor = Tunnel::start(sponsor_link, Role::Sponsor);
        let concurro = Tunnel::start(concurro_link, Role::Concurro);
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let registration = sponsor
            .register(upstream.local_addr().unwrap().port())
            .await
            .unwrap();
        let _claim = concurro.claim(registration.port()).unwrap();
        let body: Vec<u8> = (0..3 * WINDOW).map(|index| index as u8).collect();
        let sending = body.clone();
        let port = registration.port();
        let client = tokio::spawn(async move {
            let mut socket = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .await
                .unwrap();
            socket.write_all(&sending).await.unwrap();
            socket.shutdown().await.unwrap();
        });
        let (mut socket, _) = upstream.accept().await.unwrap();
        let mut received = Vec::new();
        let mut chunk = vec![0; 8192];
        loop {
            time::sleep(Duration::from_micros(50)).await;
            let count = socket.read(&mut chunk).await.unwrap();
            if count == 0 {
                break;
            }
            received.extend_from_slice(&chunk[..count]);
        }
        assert!(received == body);
        client.await.unwrap();
    })
    .await
    .unwrap();
}

/// A released registration closes the channel opened to it, and the tunnel
/// keeps serving other registrations.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn released_registration_closes_only_its_channel() {
    time::timeout(Duration::from_secs(5), async {
        let (sponsor_link, concurro_link) = tokio::io::duplex(4096);
        let sponsor = Tunnel::start(sponsor_link, Role::Sponsor);
        let concurro = Tunnel::start(concurro_link, Role::Concurro);
        let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let target = upstream.local_addr().unwrap().port();
        let released = sponsor.register(target).await.unwrap();
        let port = released.port();
        let _claim = concurro.claim(port).unwrap();
        drop(released);
        let mut socket = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let mut rest = Vec::new();
        socket.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        let live = sponsor.register(target).await.unwrap();
        let _live = concurro.claim(live.port()).unwrap();
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, live.port()))
            .await
            .unwrap();
        let (mut server, _) = upstream.accept().await.unwrap();
        client.write_all(b"still up").await.unwrap();
        let mut bytes = [0; 8];
        server.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"still up");
    })
    .await
    .unwrap();
}

/// Cancellation wakes writes blocked on the link and on its writer lock.
#[tokio::test]
async fn cancellation_wakes_registration() {
    let (left, _right) = tokio::io::duplex(1);
    let tunnel = Arc::new(Tunnel::start(left, Role::Sponsor));
    let pending = tunnel.clone();
    let first = tokio::spawn(async move { pending.register(12345).await });
    tokio::task::yield_now().await;
    let pending = tunnel.clone();
    let second = tokio::spawn(async move { pending.register(12346).await });
    tokio::task::yield_now().await;
    tunnel.cancel();
    for registration in [first, second] {
        assert!(
            time::timeout(Duration::from_secs(1), registration)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
    }
}

/// Helpers connecting to two listeners at once reach the Sponsor in the order
/// their channels were numbered.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_opens_across_listeners() {
    for _ in 0..50 {
        let (sponsor_link, concurro_link) = tokio::io::duplex(1 << 20);
        let sponsor = Tunnel::start(sponsor_link, Role::Sponsor);
        let concurro = Tunnel::start(concurro_link, Role::Concurro);
        let mut registrations = Vec::new();
        let mut claims = Vec::new();
        let mut echoes = Vec::new();
        for _ in 0..2 {
            let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let registration = sponsor
                .register(upstream.local_addr().unwrap().port())
                .await
                .unwrap();
            claims.push(concurro.claim(registration.port()).unwrap());
            registrations.push(registration);
            echoes.push(tokio::spawn(async move {
                loop {
                    let (mut socket, _) = upstream.accept().await.unwrap();
                    tokio::spawn(async move {
                        let mut body = Vec::new();
                        socket.read_to_end(&mut body).await.unwrap();
                        socket.write_all(&body).await.unwrap();
                    });
                }
            }));
        }
        let clients: Vec<_> = (0..16)
            .map(|index| {
                let port = registrations[index % 2].port();
                tokio::spawn(async move {
                    let mut socket = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                        .await
                        .unwrap();
                    socket.write_all(b"x").await.unwrap();
                    socket.shutdown().await.unwrap();
                    let mut echoed = Vec::new();
                    socket.read_to_end(&mut echoed).await.unwrap();
                    echoed
                })
            })
            .collect();
        for client in clients {
            let echoed = time::timeout(Duration::from_secs(5), client)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(echoed, b"x");
        }
        echoes.iter().for_each(|echo| echo.abort());
    }
}
