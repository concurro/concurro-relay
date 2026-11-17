//! Contract checks for native helper multiplexing.

use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use concurro_relay_native_transport::tunnel::{Frame, Kind, MAX_PAYLOAD, Role, Tunnel};
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
        let waiter = tokio::spawn(async move {
            let mapped = concurro.wait_target(target).await.unwrap();
            (concurro, mapped)
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());
        let mapped = sponsor.register(target).await.unwrap();
        let (concurro, waited) = waiter.await.unwrap();
        assert_eq!(mapped, waited);
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
        let _waiting = TcpStream::connect((Ipv4Addr::LOCALHOST, slow))
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
        let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, fast))
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

/// Closing one tunnel wakes its pending registration waiters.
#[tokio::test]
async fn cancellation_wakes_waiter() {
    let (left, _right) = tokio::io::duplex(64);
    let tunnel = Arc::new(Tunnel::start(left, Role::Concurro));
    let pending = tunnel.clone();
    let waiter = tokio::spawn(async move { pending.wait_target(12345).await });
    tokio::task::yield_now().await;
    tunnel.cancel();
    assert!(
        time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
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
