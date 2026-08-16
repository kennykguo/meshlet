use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};

fn tcp_server(bind_addr: &str) {
    let listener = TcpListener::bind(bind_addr).expect("failed to bind TCP listener");

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

fn tcp_client(server_addr: &str) {
    let mut stream = TcpStream::connect(server_addr).expect("failed to connect to TCP server");

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

fn udp_server(bind_addr: &str) {
    let socket = UdpSocket::bind(bind_addr).expect("failed to bind UDP socket");
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

fn udp_client(bind_addr: &str, server_addr: &str) {
    let socket = UdpSocket::bind(bind_addr).expect("failed to bind UDP socket");

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
    let mut args = env::args().skip(1);

    let Some(mode) = args.next() else {
        print_usage();
        return;
    };

    match mode.as_str() {
        "tcp-server" => {
            let address = args.next().unwrap_or_else(|| "127.0.0.1:8000".to_string());

            tcp_server(&address);
        }
        "tcp-client" => {
            let address = args.next().unwrap_or_else(|| "127.0.0.1:8000".to_string());

            tcp_client(&address);
        }
        "udp-server" => {
            let address = args.next().unwrap_or_else(|| "127.0.0.1:8000".to_string());

            udp_server(&address);
        }
        "udp-client" => {
            let bind_address = args.next().unwrap_or_else(|| "127.0.0.1:0".to_string());

            let server_address = args.next().unwrap_or_else(|| "127.0.0.1:8000".to_string());

            udp_client(&bind_address, &server_address);
        }
        _ => print_usage(),
    }
}

fn print_usage() {
    eprintln!(
        "Usage:
  meshlet tcp-server [BIND_ADDRESS]
  meshlet tcp-client [SERVER_ADDRESS]
  meshlet udp-server [BIND_ADDRESS]
  meshlet udp-client [BIND_ADDRESS] "
    );
}
