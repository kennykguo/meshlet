//! A pure userspace model of stateful firewall reply tracking.
//!
//! This module models decisions only; the live Linux nftables experiment lives
//! in `firewall-setup/firewall-setup.sh`.

use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

impl fmt::Display for TransportProtocol {
    /// Writes the conventional uppercase transport-protocol name.
    /// Called by Rust formatting macros when a `TransportProtocol` is displayed.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(formatter, "TCP"),
            Self::Udp => write!(formatter, "UDP"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Endpoint {
    address: Ipv4Addr,
    port: u16,
}

impl Endpoint {
    /// Constructs an IPv4 address-and-port endpoint value.
    /// Called by `firewall_demo` and firewall tests when assembling flow keys.
    pub fn new(address: Ipv4Addr, port: u16) -> Self {
        Self { address, port }
    }
}

impl fmt::Display for Endpoint {
    /// Writes an endpoint as `address:port`.
    /// Called by `FlowKey`'s formatter through Rust formatting macros.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.address, self.port)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FlowKey {
    protocol: TransportProtocol,
    source: Endpoint,
    destination: Endpoint,
}

impl FlowKey {
    /// Constructs the protocol, source, and destination that identify one flow.
    /// Called by `firewall_demo` and tests to model packet directions.
    pub fn new(protocol: TransportProtocol, source: Endpoint, destination: Endpoint) -> Self {
        Self {
            protocol,
            source,
            destination,
        }
    }

    /// Swaps source and destination while preserving the transport protocol.
    /// Called by `observe_outbound`, the demo, and tests to derive a reply flow.
    pub fn reverse(self) -> Self {
        Self {
            protocol: self.protocol,
            source: self.destination,
            destination: self.source,
        }
    }
}

impl fmt::Display for FlowKey {
    /// Writes a flow as `PROTOCOL source -> destination`.
    /// Called by Rust formatting macros in `firewall_demo` output.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {} -> {}",
            self.protocol, self.source, self.destination
        )
    }
}

pub struct Firewall {
    flow_timeout: Duration,
    allowed_replies: HashMap<FlowKey, Instant>,
}

impl Firewall {
    /// Creates an empty firewall model with a nonzero reply-state lifetime.
    /// Called by `firewall_demo` and every firewall unit test.
    pub fn new(flow_timeout: Duration) -> Self {
        assert!(!flow_timeout.is_zero(), "flow timeout must be nonzero");

        Self {
            flow_timeout,
            allowed_replies: HashMap::new(),
        }
    }

    /// Records the exact reverse flow as an allowed reply until its deadline.
    /// Called after outbound traffic by `firewall_demo` and firewall tests.
    pub fn observe_outbound(&mut self, flow: FlowKey, now: Instant) {
        self.remove_expired(now);
        let expires_at = now
            .checked_add(self.flow_timeout)
            .expect("flow expiration is outside Instant's range");
        self.allowed_replies.insert(flow.reverse(), expires_at);
    }

    /// Removes stale state and reports whether an inbound flow is an exact tracked reply.
    /// Called by `firewall_demo` and tests for every modeled inbound decision.
    pub fn allow_inbound(&mut self, flow: FlowKey, now: Instant) -> bool {
        self.remove_expired(now);
        self.allowed_replies.contains_key(&flow)
    }

    /// Returns the number of unpruned reply-flow entries currently stored.
    /// Called by `firewall_demo` and the expiration test for visible state counts.
    pub fn tracked_reply_flows(&self) -> usize {
        self.allowed_replies.len()
    }

    /// Deletes entries whose expiration deadline is at or before `now`.
    /// Called internally before outbound insertion and inbound lookup.
    fn remove_expired(&mut self, now: Instant) {
        self.allowed_replies
            .retain(|_, expires_at| *expires_at > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: Endpoint = Endpoint {
        address: Ipv4Addr::new(10, 10, 0, 2),
        port: 50_000,
    };
    const SERVER: Endpoint = Endpoint {
        address: Ipv4Addr::new(192, 0, 2, 20),
        port: 8_000,
    };

    /// Builds the shared client-to-server UDP fixture used by firewall tests.
    /// Called by each firewall unit test in this module.
    fn outbound_udp() -> FlowKey {
        FlowKey::new(TransportProtocol::Udp, CLIENT, SERVER)
    }

    /// Verifies that inbound traffic without prior outbound state is denied.
    /// Called automatically by Rust's test harness during `cargo test`.
    #[test]
    fn unsolicited_inbound_flow_is_denied() {
        let now = Instant::now();
        let mut firewall = Firewall::new(Duration::from_secs(30));

        assert!(!firewall.allow_inbound(outbound_udp().reverse(), now));
    }

    /// Verifies that an outbound flow authorizes its exact reverse flow.
    /// Called automatically by Rust's test harness during `cargo test`.
    #[test]
    fn outbound_flow_allows_its_exact_reply() {
        let now = Instant::now();
        let mut firewall = Firewall::new(Duration::from_secs(30));
        let outbound = outbound_udp();

        firewall.observe_outbound(outbound, now);

        assert!(firewall.allow_inbound(outbound.reverse(), now));
    }

    /// Verifies that changing the reply's source port produces a different flow.
    /// Called automatically by Rust's test harness during `cargo test`.
    #[test]
    fn different_source_port_is_denied() {
        let now = Instant::now();
        let mut firewall = Firewall::new(Duration::from_secs(30));
        let outbound = outbound_udp();
        let wrong_server = Endpoint::new(SERVER.address, 8_001);
        let wrong_reply = FlowKey::new(TransportProtocol::Udp, wrong_server, CLIENT);

        firewall.observe_outbound(outbound, now);

        assert!(!firewall.allow_inbound(wrong_reply, now));
    }

    /// Verifies that TCP and UDP with equal endpoints remain separate flows.
    /// Called automatically by Rust's test harness during `cargo test`.
    #[test]
    fn tcp_and_udp_flows_are_distinct() {
        let now = Instant::now();
        let mut firewall = Firewall::new(Duration::from_secs(30));
        let outbound = outbound_udp();
        let tcp_reply = FlowKey::new(TransportProtocol::Tcp, SERVER, CLIENT);

        firewall.observe_outbound(outbound, now);

        assert!(!firewall.allow_inbound(tcp_reply, now));
    }

    /// Verifies that one client's state does not authorize another client.
    /// Called automatically by Rust's test harness during `cargo test`.
    #[test]
    fn one_outbound_flow_does_not_authorize_another_flow() {
        let now = Instant::now();
        let mut firewall = Firewall::new(Duration::from_secs(30));
        let outbound = outbound_udp();
        let other_client = Endpoint::new(CLIENT.address, 50_001);
        let other_reply = FlowKey::new(TransportProtocol::Udp, SERVER, other_client);

        firewall.observe_outbound(outbound, now);

        assert!(!firewall.allow_inbound(other_reply, now));
    }

    /// Verifies that state is unavailable exactly at its expiration deadline.
    /// Called automatically by Rust's test harness during `cargo test`.
    #[test]
    fn flow_is_denied_at_its_expiration_time() {
        let now = Instant::now();
        let timeout = Duration::from_secs(30);
        let mut firewall = Firewall::new(timeout);
        let outbound = outbound_udp();

        firewall.observe_outbound(outbound, now);

        assert!(!firewall.allow_inbound(outbound.reverse(), now + timeout));
        assert_eq!(firewall.tracked_reply_flows(), 0);
    }
}
