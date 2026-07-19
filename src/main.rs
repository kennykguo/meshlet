use std::env;

fn main() {
    let mode = env::args().nth(1);

    match mode.as_deref() {
        Some("tcp-server") => println!("Starting TCP server"),
        Some("tcp-client") => println!("Starting TCP client"),
        Some("udp-server") => println!("Starting UDP server"),
        Some("udp-client") => println!("Starting UDP client"),
        _ => {
            eprintln!(
                "Usage: meshlet <tcp-server|tcp-client|udp-server|udp-client>"
            );
        }
    }
}