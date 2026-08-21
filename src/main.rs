mod coordinator;
mod firewall;
mod handshake;
mod identity;
mod relay;
mod routing;
mod secure_packet;
mod tun;

use std::env;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

const DEFAULT_RTT_SAMPLES: usize = 10_000;
const RTT_WARMUP_SAMPLES: usize = 100;

use firewall::{Endpoint, Firewall, FlowKey, TransportProtocol};

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

fn udp_bench_server(bind_addr: &str) {
    let socket = UdpSocket::bind(bind_addr).expect("failed to bind UDP benchmark socket");
    println!("local: {}", socket.local_addr().unwrap());
    println!("echoing UDP datagrams; press Ctrl-C to stop");

    let mut buffer = [0_u8; 2048];

    loop {
        let (bytes_received, remote_addr) = socket
            .recv_from(&mut buffer)
            .expect("failed to receive UDP benchmark datagram");

        socket
            .send_to(&buffer[..bytes_received], remote_addr)
            .expect("failed to echo UDP benchmark datagram");
    }
}

fn percentile(sorted: &[Duration], percentile: usize) -> Duration {
    assert!(
        !sorted.is_empty(),
        "cannot select a percentile from no samples"
    );
    assert!(percentile <= 100, "percentile must be between 0 and 100");

    let rank = sorted.len().saturating_mul(percentile).div_ceil(100);
    sorted[rank.saturating_sub(1)]
}

fn print_latency(label: &str, duration: Duration) {
    println!("{label}: {:.3} us", duration.as_secs_f64() * 1_000_000.0);
}

fn udp_rtt_client(bind_addr: &str, server_addr: &str, samples: usize) {
    assert!(samples > 0, "SAMPLES must be greater than zero");

    let socket = UdpSocket::bind(bind_addr).expect("failed to bind UDP RTT socket");
    socket
        .connect(server_addr)
        .expect("failed to select UDP RTT peer");
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("failed to set UDP RTT receive timeout");

    println!("local: {}", socket.local_addr().unwrap());
    println!("remote: {}", socket.peer_addr().unwrap());
    println!("warmup samples: {RTT_WARMUP_SAMPLES}"); // constant
    println!("measured samples: {samples}");

    let total_samples = RTT_WARMUP_SAMPLES
        .checked_add(samples)
        .expect("sample count is too large");
    let mut response = [0_u8; size_of::<u64>()];
    let mut latencies = Vec::with_capacity(samples);

    for sequence in 0..total_samples {
        let sequence = u64::try_from(sequence).expect("sequence number does not fit in u64");
        let request = sequence.to_be_bytes();

        // start the timer
        let start = Instant::now();

        // send the request
        socket
            .send(&request)
            .expect("failed to send UDP RTT request");
        let bytes_received = socket // wait for echo response
            .recv(&mut response)
            .expect("failed to receive UDP RTT response within one second");

        // stop the timer
        let elapsed = start.elapsed();

        assert_eq!(
            bytes_received,
            request.len(),
            "unexpected RTT response size"
        );
        assert_eq!(response, request, "RTT response did not match its request");

        if sequence >= RTT_WARMUP_SAMPLES as u64 {
            latencies.push(elapsed);
        }
    }

    latencies.sort_unstable();

    print_latency("min", latencies[0]);
    print_latency("p50", percentile(&latencies, 50));
    print_latency("p99", percentile(&latencies, 99));
    print_latency("max", latencies[latencies.len() - 1]);
}

fn verdict(allowed: bool) -> &'static str {
    if allowed { "ALLOW" } else { "DENY" }
}

fn firewall_demo() {
    let now = Instant::now();
    let timeout = Duration::from_secs(30);
    let client = Endpoint::new(Ipv4Addr::new(10, 10, 0, 2), 50_000);
    let server = Endpoint::new(Ipv4Addr::new(192, 0, 2, 20), 8_000);
    let outbound = FlowKey::new(TransportProtocol::Udp, client, server);
    let matching_reply = outbound.reverse();
    let wrong_port_reply = FlowKey::new(
        // reverse the endpoint
        TransportProtocol::Udp,
        Endpoint::new(Ipv4Addr::new(192, 0, 2, 20), 8_001),
        client,
    );
    let tcp_reply = FlowKey::new(TransportProtocol::Tcp, server, client);
    let mut firewall = Firewall::new(timeout);

    println!("simplified stateful firewall demo");
    println!("flow timeout: {} seconds", timeout.as_secs());
    println!();

    println!("1. unsolicited inbound reply-shaped packet");
    println!("   flow: {matching_reply}");
    println!(
        "   decision: {} (no matching state exists)",
        verdict(firewall.allow_inbound(matching_reply, now))
    );
    println!();

    println!("2. private client initiates an outbound flow");
    println!("   flow: {outbound}");
    firewall.observe_outbound(outbound, now);
    println!("   decision: ALLOW");
    println!(
        "   state installed for reply: {matching_reply} ({} tracked flow)",
        firewall.tracked_reply_flows()
    );
    println!();

    println!("3. exact reply arrives");
    println!("   flow: {matching_reply}");
    println!(
        "   decision: {} (matches recorded reply state)",
        verdict(firewall.allow_inbound(matching_reply, now))
    );
    println!();

    println!("4. reply comes from a different UDP source port");
    println!("   flow: {wrong_port_reply}");
    println!(
        "   decision: {} (five-tuple differs)",
        verdict(firewall.allow_inbound(wrong_port_reply, now))
    );
    println!();

    println!("5. addresses and ports match, but the protocol is TCP");
    println!("   flow: {tcp_reply}");
    println!(
        "   decision: {} (TCP and UDP are separate flows)",
        verdict(firewall.allow_inbound(tcp_reply, now))
    );
    println!();

    println!("6. exact UDP reply arrives at the 30-second expiration boundary");
    println!("   flow: {matching_reply}");
    println!(
        "   decision: {} (recorded state has expired)",
        verdict(firewall.allow_inbound(matching_reply, now + timeout))
    );
    println!("   tracked flows: {}", firewall.tracked_reply_flows());
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
        "udp-bench-server" => {
            let address = args.next().unwrap_or_else(|| "127.0.0.1:8000".to_string());

            udp_bench_server(&address);
        }
        "udp-rtt-client" => {
            let bind_address = args.next().unwrap_or_else(|| "127.0.0.1:0".to_string());
            let server_address = args.next().unwrap_or_else(|| "127.0.0.1:8000".to_string());
            let samples = args
                .next()
                .map(|value| value.parse().expect("SAMPLES must be a positive integer"))
                .unwrap_or(DEFAULT_RTT_SAMPLES);

            udp_rtt_client(&bind_address, &server_address, samples);
        }
        "firewall-demo" => firewall_demo(),
        "identity-generate" => {
            let node_id = args.next().unwrap_or_else(|| "mesh-a".to_string());
            let private_path = args
                .next()
                .unwrap_or_else(|| format!(".meshlet/keys/{node_id}.identity"));
            let public_path = args
                .next()
                .unwrap_or_else(|| format!(".meshlet/keys/{node_id}.authorization"));

            identity::generate(&node_id, &private_path, &public_path)
                .unwrap_or_else(|error| panic!("failed to generate identity: {error}"));
        }
        "coordinator-server" => {
            let bind_address = args.next().unwrap_or_else(|| "127.0.0.1:9000".to_string());

            coordinator::run_server(&bind_address);
        }
        "coordinator-register" => {
            let bind_address = args.next().unwrap_or_else(|| "127.0.0.1:0".to_string());
            let server_address = args.next().unwrap_or_else(|| "127.0.0.1:9000".to_string());
            let node_id = args.next().unwrap_or_else(|| "mesh-a".to_string());
            let lease_seconds = args
                .next()
                .map(|value| {
                    value
                        .parse()
                        .expect("LEASE_SECONDS must be a positive integer")
                })
                .unwrap_or(30);

            coordinator::register(&bind_address, &server_address, &node_id, lease_seconds);
        }
        "coordinator-lookup" => {
            let bind_address = args.next().unwrap_or_else(|| "127.0.0.1:0".to_string());
            let server_address = args.next().unwrap_or_else(|| "127.0.0.1:9000".to_string());
            let node_id = args.next().unwrap_or_else(|| "mesh-a".to_string());

            coordinator::lookup(&bind_address, &server_address, &node_id);
        }
        "coordinator-server-auth" => {
            let bind_address = args.next().unwrap_or_else(|| "127.0.0.1:9000".to_string());
            let authorization_path = args
                .next()
                .unwrap_or_else(|| ".meshlet/keys/authorized-nodes".to_string());

            coordinator::run_authenticated_server(&bind_address, &authorization_path);
        }
        "coordinator-route-server" => {
            let bind_address = args.next().unwrap_or_else(|| "127.0.0.1:9000".to_string());
            coordinator::run_server(&bind_address);
        }
        "coordinator-register-auth" => {
            let bind_address = args.next().unwrap_or_else(|| "127.0.0.1:0".to_string());
            let server_address = args.next().unwrap_or_else(|| "127.0.0.1:9000".to_string());
            let node_id = args.next().unwrap_or_else(|| "mesh-a".to_string());
            let lease_seconds = args
                .next()
                .map(|value| {
                    value
                        .parse()
                        .expect("LEASE_SECONDS must be a positive integer")
                })
                .unwrap_or(30);
            let identity_path = args
                .next()
                .unwrap_or_else(|| format!(".meshlet/keys/{node_id}.identity"));

            coordinator::register_authenticated(
                &bind_address,
                &server_address,
                &node_id,
                lease_seconds,
                &identity_path,
            );
        }
        "coordinator-lookup-auth" => {
            let bind_address = args.next().unwrap_or_else(|| "127.0.0.1:0".to_string());
            let server_address = args.next().unwrap_or_else(|| "127.0.0.1:9000".to_string());
            let node_id = args.next().unwrap_or_else(|| "mesh-a".to_string());

            coordinator::lookup_authenticated(&bind_address, &server_address, &node_id);
        }
        "coordinator-advertise-route" => {
            let bind_address = args.next().unwrap_or_else(|| "127.0.0.1:0".to_string());
            let server_address = args.next().unwrap_or_else(|| "127.0.0.1:9000".to_string());
            let node_id = args.next().unwrap_or_else(|| "mesh-b".to_string());
            let prefix = args.next().unwrap_or_else(|| "10.30.0.0/24".to_string());
            let lease_seconds = args
                .next()
                .map(|value| {
                    value
                        .parse()
                        .expect("LEASE_SECONDS must be a positive integer")
                })
                .unwrap_or(120);
            coordinator::advertise_route(
                &bind_address,
                &server_address,
                &node_id,
                &prefix,
                lease_seconds,
            );
        }
        "coordinator-route-lookup" => {
            let bind_address = args.next().unwrap_or_else(|| "127.0.0.1:0".to_string());
            let server_address = args.next().unwrap_or_else(|| "127.0.0.1:9000".to_string());
            let destination = args.next().unwrap_or_else(|| "10.30.0.2".to_string());

            coordinator::route_lookup(&bind_address, &server_address, &destination);
        }
        "secure-echo-server" => {
            let bind_address = args.next().unwrap_or_else(|| "127.0.0.1:7000".to_string());
            let identity_path = args
                .next()
                .unwrap_or_else(|| ".meshlet/keys/mesh-b.identity".to_string());
            let authorization_path = args
                .next()
                .unwrap_or_else(|| ".meshlet/keys/authorized-nodes".to_string());

            handshake::run_secure_echo_server(&bind_address, &identity_path, &authorization_path);
        }
        "secure-echo-client" => {
            let bind_address = args.next().unwrap_or_else(|| "127.0.0.1:0".to_string());
            let server_address = args.next().unwrap_or_else(|| "127.0.0.1:7000".to_string());
            let identity_path = args
                .next()
                .unwrap_or_else(|| ".meshlet/keys/mesh-a.identity".to_string());
            let peer_node_id = args.next().unwrap_or_else(|| "mesh-b".to_string());
            let authorization_path = args
                .next()
                .unwrap_or_else(|| ".meshlet/keys/mesh-b.authorization".to_string());

            handshake::run_secure_echo_client(
                &bind_address,
                &server_address,
                &identity_path,
                &peer_node_id,
                &authorization_path,
            );
        }
        "secure-echo-client-auto" => {
            let bind_address = args.next().unwrap_or_else(|| "127.0.0.1:0".to_string());
            let direct_address = args.next().unwrap_or_else(|| "127.0.0.1:7000".to_string());
            let relay_address = args.next().unwrap_or_else(|| "127.0.0.1:7100".to_string());
            let identity_path = args
                .next()
                .unwrap_or_else(|| ".meshlet/keys/mesh-a.identity".to_string());
            let peer_node_id = args.next().unwrap_or_else(|| "mesh-b".to_string());
            let authorization_path = args
                .next()
                .unwrap_or_else(|| ".meshlet/keys/mesh-b.authorization".to_string());

            handshake::run_secure_echo_client_auto(
                &bind_address,
                &direct_address,
                &relay_address,
                &identity_path,
                &peer_node_id,
                &authorization_path,
            );
        }
        "udp-relay" => {
            let bind_address = args.next().unwrap_or_else(|| "127.0.0.1:7100".to_string());
            let upstream_address = args.next().unwrap_or_else(|| "127.0.0.1:7000".to_string());

            relay::run(&bind_address, &upstream_address);
        }
        "tun-udp-one" => {
            let tun_name = args.next().unwrap_or_else(|| "meshlet0".to_string());
            let bind_address = args.next().unwrap_or_else(|| "127.0.0.1:7200".to_string());
            let peer_address = args.next().unwrap_or_else(|| "127.0.0.1:7201".to_string());

            tun::run_one_exchange(&tun_name, &bind_address, &peer_address);
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
  meshlet udp-client [BIND_ADDRESS] [SERVER_ADDRESS]
  meshlet udp-bench-server [BIND_ADDRESS]
  meshlet udp-rtt-client [BIND_ADDRESS] [SERVER_ADDRESS] [SAMPLES]
  meshlet firewall-demo
  meshlet identity-generate [NODE_ID] [PRIVATE_PATH] [AUTHORIZATION_PATH]
  meshlet coordinator-server [BIND_ADDRESS]
  meshlet coordinator-register [BIND_ADDRESS] [SERVER_ADDRESS] [NODE_ID] [LEASE_SECONDS]
  meshlet coordinator-lookup [BIND_ADDRESS] [SERVER_ADDRESS] [NODE_ID]
  meshlet coordinator-server-auth [BIND_ADDRESS] [AUTHORIZATION_PATH]
  meshlet coordinator-route-server [BIND_ADDRESS]
  meshlet coordinator-register-auth [BIND_ADDRESS] [SERVER_ADDRESS] [NODE_ID] [LEASE_SECONDS] [IDENTITY_PATH]
  meshlet coordinator-lookup-auth [BIND_ADDRESS] [SERVER_ADDRESS] [NODE_ID]
  meshlet coordinator-advertise-route [BIND_ADDRESS] [SERVER_ADDRESS] [NODE_ID] [PREFIX] [LEASE_SECONDS]
  meshlet coordinator-route-lookup [BIND_ADDRESS] [SERVER_ADDRESS] [DESTINATION]
  meshlet secure-echo-server [BIND_ADDRESS] [IDENTITY_PATH] [AUTHORIZATION_PATH]
  meshlet secure-echo-client [BIND_ADDRESS] [SERVER_ADDRESS] [IDENTITY_PATH] [PEER_NODE_ID] [AUTHORIZATION_PATH]
  meshlet secure-echo-client-auto [BIND_ADDRESS] [DIRECT_ADDRESS] [RELAY_ADDRESS] [IDENTITY_PATH] [PEER_NODE_ID] [AUTHORIZATION_PATH]
  meshlet udp-relay [BIND_ADDRESS] [UPSTREAM_ADDRESS]
  meshlet tun-udp-one [TUN_NAME] [BIND_ADDRESS] [PEER_ADDRESS]"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_uses_nearest_rank() {
        let samples: Vec<_> = (1..=100).map(Duration::from_nanos).collect();

        assert_eq!(percentile(&samples, 0), Duration::from_nanos(1));
        assert_eq!(percentile(&samples, 50), Duration::from_nanos(50));
        assert_eq!(percentile(&samples, 99), Duration::from_nanos(99));
        assert_eq!(percentile(&samples, 100), Duration::from_nanos(100));
    }
}
