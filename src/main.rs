use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};

fn tcp_server() {
    let listener = TcpListener::bind("127.0.0.1:8000").expect("failed to bind TCP listener");

    println!("local: {}", listener.local_addr().unwrap());

    let (mut stream, remote_addr) = listener.accept().expect("failed to accept connection");

    println!("remote: {remote_addr}");

    let mut buffer = [0_u8; 1024];

    let bytes_received = stream
        .read(&mut buffer)
        .expect("failed to read from TCP stream");

    println!("bytes received: {bytes_received}");
    println!("exact bytes: {:?}", &buffer[..bytes_received]);

    stream // write back to the client
        .write_all(&buffer[..bytes_received])
        .expect("failed to echo TCP bytes");

    println!("bytes sent: {bytes_received}");
}

fn tcp_client() {
    // ephermal port is created. 8000 is the remote here when you call this
    let mut stream = TcpStream::connect("127.0.0.1:8000").expect("failed to connect to TCP server");

    println!("local: {}", stream.local_addr().unwrap());
    println!("remote: {}", stream.peer_addr().unwrap());

    let message = b"hello from tcp client\n";

    stream.write_all(message).expect("failed to send TCP bytes");

    println!("bytes sent: {}", message.len());

    let mut response = Vec::new();

    let bytes_received = stream // check for a response after sending
        .read_to_end(&mut response)
        .expect("failed to read TCP response");

    println!("bytes received: {bytes_received}");
    println!("exact bytes: {response:?}");
}

fn udp_server() {
    let socket = UdpSocket::bind("127.0.0.1:8000").expect("failed to bind UDP socket");

    println!("local: {}", socket.local_addr().unwrap());

    let mut buffer = [0_u8; 1024];

    let (bytes_received, remote_addr) = socket
        .recv_from(&mut buffer)
        .expect("failed to receive UDP datagram");

    println!("remote: {remote_addr}");
    println!("bytes received: {bytes_received}");
    println!("exact bytes: {:?}", &buffer[..bytes_received]);

    let bytes_sent = socket
        .send_to(&buffer[..bytes_received], remote_addr)
        .expect("failed to echo UDP datagram");

    println!("bytes sent: {bytes_sent}");
}

fn udp_client() {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("failed to bind UDP socket"); // choose an ephermal port

    let server_addr = "127.0.0.1:8000";
    let message = b"hello from udp client\n";

    println!("local: {}", socket.local_addr().unwrap());
    println!("remote: {server_addr}");

    let bytes_sent = socket // socket syntax. but same as tcp
        .send_to(message, server_addr)
        .expect("failed to send UDP datagram");

    println!("bytes sent: {bytes_sent}");

    let mut buffer = [0_u8; 1024];

    let (bytes_received, remote_addr) = socket
        .recv_from(&mut buffer)
        .expect("failed to receive UDP response");

    println!("response from: {remote_addr}");
    println!("bytes received: {bytes_received}");
    println!("exact bytes: {:?}", &buffer[..bytes_received]);
}

fn main() {
    let mode = env::args().nth(1); // 1st argument - 0 is the program name

    match mode.as_deref() {
        Some("tcp-server") => tcp_server(),
        Some("tcp-client") => tcp_client(),
        Some("udp-server") => udp_server(),
        Some("udp-client") => udp_client(),
        _ => eprintln!("Usage: meshlet <tcp-server|tcp-client|udp-server|udp-client>"),
    }
}
