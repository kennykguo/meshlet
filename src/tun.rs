//! Carry one IPv4 packet in each direction between a Linux TUN device and UDP.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, UdpSocket};
use std::os::fd::AsRawFd;
use std::thread;

const TUN_DEVICE_PATH: &str = "/dev/net/tun";
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const MAX_UDP_PAYLOAD_BYTES: usize = 65_507;

#[derive(Debug, Eq, PartialEq)]
struct Ipv4Summary {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    total_length: usize,
}

pub fn run_one_exchange(tun_name: &str, bind_address: &str, peer_address: &str) {
    let tun = open_tun(tun_name)
        .unwrap_or_else(|error| panic!("failed to attach to TUN interface '{tun_name}': {error}"));
    let socket = UdpSocket::bind(bind_address).expect("failed to bind TUN transport UDP socket");
    socket
        .connect(peer_address)
        .expect("failed to select TUN transport peer");

    println!("TUN interface: {tun_name}");
    println!("UDP transport local: {}", socket.local_addr().unwrap());
    println!("UDP transport peer: {}", socket.peer_addr().unwrap());
    println!("waiting for one IPv4 packet in each direction");

    let mut tun_reader = tun.try_clone().expect("failed to clone TUN descriptor");
    let outbound_socket = socket
        .try_clone()
        .expect("failed to clone UDP transport socket");
    let outbound = thread::spawn(move || {
        let mut packet = [0_u8; MAX_UDP_PAYLOAD_BYTES + 1];
        let (bytes_read, summary) = loop {
            let bytes_read = tun_reader
                .read(&mut packet)
                .expect("failed to read packet from TUN interface");
            require_transportable_packet(&packet[..bytes_read])
                .unwrap_or_else(|error| panic!("cannot transport TUN packet: {error}"));
            match parse_ipv4(&packet[..bytes_read]) {
                Ok(summary) => break (bytes_read, summary),
                Err(error) if packet.first().is_some_and(|byte| byte >> 4 != 4) => {
                    println!("ignored non-IPv4 TUN packet: {error}");
                }
                Err(error) => panic!("invalid outbound IPv4 packet: {error}"),
            }
        };

        outbound_socket
            .send(&packet[..bytes_read])
            .expect("failed to send TUN packet over UDP");
        println!(
            "TUN -> UDP: {} -> {}, IP protocol {}, {} bytes",
            summary.source, summary.destination, summary.protocol, bytes_read
        );
    });

    let mut tun_writer = tun;
    let inbound = thread::spawn(move || {
        let mut packet = [0_u8; MAX_UDP_PAYLOAD_BYTES + 1];
        let bytes_received = socket
            .recv(&mut packet)
            .expect("failed to receive tunneled UDP payload");
        require_transportable_packet(&packet[..bytes_received])
            .unwrap_or_else(|error| panic!("cannot inject tunneled packet: {error}"));
        let summary = parse_ipv4(&packet[..bytes_received])
            .unwrap_or_else(|error| panic!("invalid inbound IPv4 packet: {error}"));

        tun_writer
            .write_all(&packet[..bytes_received])
            .expect("failed to write packet into TUN interface");
        println!(
            "UDP -> TUN: {} -> {}, IP protocol {}, {} bytes",
            summary.source, summary.destination, summary.protocol, bytes_received
        );
    });

    outbound.join().expect("TUN-to-UDP worker panicked");
    inbound.join().expect("UDP-to-TUN worker panicked");
}

fn open_tun(name: &str) -> io::Result<File> {
    if name.is_empty() || name.len() >= libc::IFNAMSIZ || !name.is_ascii() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "interface name must contain 1-{} ASCII bytes",
                libc::IFNAMSIZ - 1
            ),
        ));
    }

    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(TUN_DEVICE_PATH)?;

    // SAFETY: `libc::ifreq` is the C structure required by Linux's TUNSETIFF
    // interface. It is zero-initialized, the name is bounded by IFNAMSIZ, and
    // the file descriptor and pointer remain valid for the ioctl call.
    let result = unsafe {
        let mut request: libc::ifreq = std::mem::zeroed();
        for (destination, source) in request.ifr_name.iter_mut().zip(name.bytes()) {
            *destination = source as libc::c_char;
        }
        request.ifr_ifru.ifru_flags = IFF_TUN | IFF_NO_PI;
        libc::ioctl(file.as_raw_fd(), TUNSETIFF, &mut request)
    };

    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(file)
    }
}

fn require_transportable_packet(packet: &[u8]) -> Result<(), String> {
    if packet.len() > MAX_UDP_PAYLOAD_BYTES {
        Err(format!(
            "packet exceeds UDP's {MAX_UDP_PAYLOAD_BYTES}-byte payload limit"
        ))
    } else {
        Ok(())
    }
}

fn parse_ipv4(packet: &[u8]) -> Result<Ipv4Summary, String> {
    if packet.len() < 20 {
        return Err("packet is shorter than the minimum 20-byte IPv4 header".into());
    }
    if packet[0] >> 4 != 4 {
        return Err("packet is not IPv4".into());
    }

    let header_length = usize::from(packet[0] & 0x0f) * 4;
    if header_length < 20 || header_length > packet.len() {
        return Err("IPv4 header length is invalid".into());
    }
    let total_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_length < header_length || total_length != packet.len() {
        return Err(format!(
            "IPv4 total length says {total_length} bytes, but TUN supplied {}",
            packet.len()
        ));
    }

    Ok(Ipv4Summary {
        source: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        destination: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        protocol: packet[9],
        total_length,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_fields_needed_to_observe_an_ipv4_packet() {
        let mut packet = [0_u8; 28];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
        packet[9] = 1;
        packet[12..16].copy_from_slice(&[100, 64, 0, 1]);
        packet[16..20].copy_from_slice(&[100, 64, 0, 2]);

        assert_eq!(
            parse_ipv4(&packet),
            Ok(Ipv4Summary {
                source: Ipv4Addr::new(100, 64, 0, 1),
                destination: Ipv4Addr::new(100, 64, 0, 2),
                protocol: 1,
                total_length: 28,
            })
        );
    }

    #[test]
    fn rejects_a_non_ipv4_packet() {
        let mut packet = [0_u8; 40];
        packet[0] = 0x60;

        assert_eq!(parse_ipv4(&packet), Err("packet is not IPv4".into()));
    }
}
