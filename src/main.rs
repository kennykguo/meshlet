use std::env;
use std::net::TcpListener;
use std::io::Read;


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
}

fn main() {
    let mode = env::args().nth(1); // 1st argument - 0 is the program name

    match mode.as_deref() {
        Some("tcp-server") => tcp_server(),
        Some("tcp-client") => println!("Starting TCP client"),
        Some("udp-server") => println!("Starting UDP server"),
        Some("udp-client") => println!("Starting UDP client"),
        _ => eprintln!("Usage: meshlet <tcp-server|tcp-client|udp-server|udp-client>"),
    }
}
