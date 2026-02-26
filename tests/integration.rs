use std::net::UdpSocket;
use std::process::{Child, Command};
use std::time::Duration;

fn spawn_forwarder(args: &[&str]) -> Child {
    Command::new(env!("CARGO_BIN_EXE_udp-forward"))
        .args(args)
        .args(["-w", "1"]) // Single worker for deterministic tests
        .spawn()
        .expect("Failed to spawn forwarder")
}

fn recv_with_timeout(socket: &UdpSocket, timeout: Duration) -> Option<Vec<u8>> {
    socket.set_read_timeout(Some(timeout)).unwrap();
    let mut buf = [0u8; 65536];
    match socket.recv(&mut buf) {
        Ok(len) => Some(buf[..len].to_vec()),
        Err(_) => None,
    }
}

#[test]
fn test_basic_forwarding_ipv4() {
    let receiver = UdpSocket::bind("127.0.0.1:5001").expect("Failed to bind receiver");

    let mut child = spawn_forwarder(&["-l", "127.0.0.1:4001", "127.0.0.1:5001"]);
    std::thread::sleep(Duration::from_millis(100));

    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    sender
        .send_to(b"test_ipv4_basic", "127.0.0.1:4001")
        .unwrap();

    let data = recv_with_timeout(&receiver, Duration::from_secs(2));
    child.kill().ok();

    assert!(data.is_some(), "No packet received");
    assert_eq!(data.unwrap(), b"test_ipv4_basic");
}

#[test]
fn test_multiple_destinations_ipv4() {
    let receiver1 = UdpSocket::bind("127.0.0.1:5002").expect("Failed to bind receiver1");
    let receiver2 = UdpSocket::bind("127.0.0.1:5003").expect("Failed to bind receiver2");

    let mut child = spawn_forwarder(&["-l", "127.0.0.1:4002", "127.0.0.1:5002", "127.0.0.1:5003"]);
    std::thread::sleep(Duration::from_millis(200));

    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    sender
        .send_to(b"test_ipv4_multi", "127.0.0.1:4002")
        .unwrap();

    let data1 = recv_with_timeout(&receiver1, Duration::from_secs(2));
    let data2 = recv_with_timeout(&receiver2, Duration::from_secs(2));
    child.kill().ok();

    assert!(data1.is_some(), "Receiver 1 got no packet");
    assert!(data2.is_some(), "Receiver 2 got no packet");
    assert_eq!(data1.unwrap(), b"test_ipv4_multi");
    assert_eq!(data2.unwrap(), b"test_ipv4_multi");
}

#[test]
fn test_multiple_packets_ipv4() {
    let receiver = UdpSocket::bind("127.0.0.1:5004").expect("Failed to bind receiver");

    let mut child = spawn_forwarder(&["-l", "127.0.0.1:4003", "127.0.0.1:5004"]);
    std::thread::sleep(Duration::from_millis(100));

    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    for i in 0..5 {
        let msg = format!("packet_{}", i);
        sender.send_to(msg.as_bytes(), "127.0.0.1:4003").unwrap();
        std::thread::sleep(Duration::from_millis(10));
    }

    let mut received = 0;
    for _ in 0..5 {
        if recv_with_timeout(&receiver, Duration::from_millis(500)).is_some() {
            received += 1;
        }
    }
    child.kill().ok();

    assert_eq!(received, 5, "Expected 5 packets, got {}", received);
}

#[test]
fn test_port_in_use_ipv4() {
    let _blocker = UdpSocket::bind("127.0.0.1:4004").expect("Failed to bind blocker");

    let output = Command::new(env!("CARGO_BIN_EXE_udp-forward"))
        .args(["-l", "127.0.0.1:4004", "127.0.0.1:5005"])
        .output()
        .expect("Failed to run");

    assert!(!output.status.success(), "Should fail when port is in use");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("in use") || stderr.contains("already in use"),
        "Error should mention 'in use', got: {}",
        stderr
    );
}

#[test]
#[ignore]
fn test_silent_mode_ipv4() {
    let original_server = UdpSocket::bind("127.0.0.1:4005").expect("Failed to bind original");
    let receiver = UdpSocket::bind("127.0.0.1:5006").expect("Failed to bind receiver");

    let mut child = spawn_forwarder(&["-l", "127.0.0.1:4005", "-S", "127.0.0.1:5006"]);
    std::thread::sleep(Duration::from_millis(200));

    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    sender.send_to(b"test_silent_v4", "127.0.0.1:4005").unwrap();

    let forwarded = recv_with_timeout(&receiver, Duration::from_secs(2));
    let original = recv_with_timeout(&original_server, Duration::from_secs(2));
    child.kill().ok();

    assert!(forwarded.is_some(), "Forwarder didn't receive packet");
    assert_eq!(forwarded.unwrap(), b"test_silent_v4");
    assert!(original.is_some(), "Original server didn't receive packet");
}

#[test]
#[ignore]
fn test_spoofed_source_ipv4() {
    let receiver = UdpSocket::bind("127.0.0.1:5007").expect("Failed to bind receiver");

    let mut child = spawn_forwarder(&["-l", "127.0.0.1:4006", "-s", "127.0.0.1:5007"]);
    std::thread::sleep(Duration::from_millis(100));

    let sender = UdpSocket::bind("127.0.0.1:12345").unwrap();
    sender.send_to(b"test_spoof_v4", "127.0.0.1:4006").unwrap();

    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 65536];
    let result = receiver.recv_from(&mut buf);
    child.kill().ok();

    let (len, src_addr) = result.expect("Failed to receive");
    assert_eq!(&buf[..len], b"test_spoof_v4");
    assert_eq!(
        src_addr.to_string(),
        "127.0.0.1:12345",
        "Source address should be preserved"
    );
}

#[test]
fn test_basic_forwarding_ipv6() {
    let receiver = UdpSocket::bind("[::1]:5101").expect("Failed to bind receiver");

    let mut child = spawn_forwarder(&["-l", "[::1]:4101", "[::1]:5101"]);
    std::thread::sleep(Duration::from_millis(100));

    let sender = UdpSocket::bind("[::1]:0").unwrap();
    sender.send_to(b"test_ipv6_basic", "[::1]:4101").unwrap();

    let data = recv_with_timeout(&receiver, Duration::from_secs(2));
    child.kill().ok();

    assert!(data.is_some(), "No packet received");
    assert_eq!(data.unwrap(), b"test_ipv6_basic");
}

#[test]
fn test_multiple_destinations_ipv6() {
    let receiver1 = UdpSocket::bind("[::1]:5102").expect("Failed to bind receiver1");
    let receiver2 = UdpSocket::bind("[::1]:5103").expect("Failed to bind receiver2");

    let mut child = spawn_forwarder(&["-l", "[::1]:4102", "[::1]:5102", "[::1]:5103"]);
    std::thread::sleep(Duration::from_millis(200));

    let sender = UdpSocket::bind("[::1]:0").unwrap();
    sender.send_to(b"test_ipv6_multi", "[::1]:4102").unwrap();

    let data1 = recv_with_timeout(&receiver1, Duration::from_secs(2));
    let data2 = recv_with_timeout(&receiver2, Duration::from_secs(2));
    child.kill().ok();

    assert!(data1.is_some(), "Receiver 1 got no packet");
    assert!(data2.is_some(), "Receiver 2 got no packet");
    assert_eq!(data1.unwrap(), b"test_ipv6_multi");
    assert_eq!(data2.unwrap(), b"test_ipv6_multi");
}

#[test]
fn test_multiple_packets_ipv6() {
    let receiver = UdpSocket::bind("[::1]:5104").expect("Failed to bind receiver");

    let mut child = spawn_forwarder(&["-l", "[::1]:4103", "[::1]:5104"]);
    std::thread::sleep(Duration::from_millis(100));

    let sender = UdpSocket::bind("[::1]:0").unwrap();
    for i in 0..5 {
        let msg = format!("packet_{}", i);
        sender.send_to(msg.as_bytes(), "[::1]:4103").unwrap();
        std::thread::sleep(Duration::from_millis(10));
    }

    let mut received = 0;
    for _ in 0..5 {
        if recv_with_timeout(&receiver, Duration::from_millis(500)).is_some() {
            received += 1;
        }
    }
    child.kill().ok();

    assert_eq!(received, 5, "Expected 5 packets, got {}", received);
}

#[test]
#[ignore]
fn test_silent_mode_ipv6() {
    let original_server = UdpSocket::bind("[::1]:4105").expect("Failed to bind original");
    let receiver = UdpSocket::bind("[::1]:5106").expect("Failed to bind receiver");

    let mut child = spawn_forwarder(&["-l", "[::1]:4105", "-S", "[::1]:5106"]);
    std::thread::sleep(Duration::from_millis(200));

    let sender = UdpSocket::bind("[::1]:0").unwrap();
    sender.send_to(b"test_silent_v6", "[::1]:4105").unwrap();

    let forwarded = recv_with_timeout(&receiver, Duration::from_secs(2));
    let original = recv_with_timeout(&original_server, Duration::from_secs(2));
    child.kill().ok();

    assert!(forwarded.is_some(), "Forwarder didn't receive packet");
    assert_eq!(forwarded.unwrap(), b"test_silent_v6");
    assert!(original.is_some(), "Original server didn't receive packet");
}

#[test]
#[ignore]
fn test_spoofed_source_ipv6() {
    let receiver = UdpSocket::bind("[::1]:5107").expect("Failed to bind receiver");

    let mut child = spawn_forwarder(&["-l", "[::1]:4106", "-s", "[::1]:5107"]);
    std::thread::sleep(Duration::from_millis(100));

    let sender = UdpSocket::bind("[::1]:12346").unwrap();
    sender.send_to(b"test_spoof_v6", "[::1]:4106").unwrap();

    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 65536];
    let result = receiver.recv_from(&mut buf);
    child.kill().ok();

    let (len, src_addr) = result.expect("Failed to receive");
    assert_eq!(&buf[..len], b"test_spoof_v6");
    assert_eq!(
        src_addr.to_string(),
        "[::1]:12346",
        "Source address should be preserved"
    );
}

#[test]
#[ignore]
fn test_silent_and_spoof_ipv4() {
    let original_server = UdpSocket::bind("127.0.0.1:4007").expect("Failed to bind original");
    let receiver = UdpSocket::bind("127.0.0.1:5008").expect("Failed to bind receiver");

    let mut child = spawn_forwarder(&["-l", "127.0.0.1:4007", "-S", "-s", "127.0.0.1:5008"]);
    std::thread::sleep(Duration::from_millis(200));

    let sender = UdpSocket::bind("127.0.0.1:23456").unwrap();
    sender
        .send_to(b"test_silent_spoof_v4", "127.0.0.1:4007")
        .unwrap();

    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 65536];
    let forwarded = receiver.recv_from(&mut buf);

    let original = recv_with_timeout(&original_server, Duration::from_secs(2));
    child.kill().ok();

    let (len, src_addr) = forwarded.expect("Forwarder didn't forward packet");
    assert_eq!(&buf[..len], b"test_silent_spoof_v4");
    assert_eq!(
        src_addr.to_string(),
        "127.0.0.1:23456",
        "Source address should be preserved (spoofed)"
    );
    assert!(original.is_some(), "Original server didn't receive packet");
}

#[test]
#[ignore]
fn test_silent_and_spoof_ipv6() {
    let original_server = UdpSocket::bind("[::1]:4107").expect("Failed to bind original");
    let receiver = UdpSocket::bind("[::1]:5108").expect("Failed to bind receiver");

    let mut child = spawn_forwarder(&["-l", "[::1]:4107", "-S", "-s", "[::1]:5108"]);
    std::thread::sleep(Duration::from_millis(200));

    let sender = UdpSocket::bind("[::1]:23457").unwrap();
    sender
        .send_to(b"test_silent_spoof_v6", "[::1]:4107")
        .unwrap();

    receiver
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut buf = [0u8; 65536];
    let forwarded = receiver.recv_from(&mut buf);

    let original = recv_with_timeout(&original_server, Duration::from_secs(2));
    child.kill().ok();

    let (len, src_addr) = forwarded.expect("Forwarder didn't forward packet");
    assert_eq!(&buf[..len], b"test_silent_spoof_v6");
    assert_eq!(
        src_addr.to_string(),
        "[::1]:23457",
        "Source address should be preserved (spoofed)"
    );
    assert!(original.is_some(), "Original server didn't receive packet");
}
