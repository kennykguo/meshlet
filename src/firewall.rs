use std::collections::HashMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

// transport protocol
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

impl fmt::Display for TransportProtocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(formatter, "TCP"),
            Self::Udp => write!(formatter, "UDP"),
        }
    }
}

// endpoint
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Endpoint {
    address: Ipv4Addr,
    port: u16,
}

impl Endpoint {
    pub fn new(address: Ipv4Addr, port: u16) -> Self {
        Self { address, port }
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.address, self.port)
    }
}

// flow - 5 tuple
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FlowKey {
    protocol: TransportProtocol,
    source: Endpoint,
    destination: Endpoint,
}

impl FlowKey {
    pub fn new(protocol: TransportProtocol, source: Endpoint, destination: Endpoint) -> Self {
        Self {
            protocol,
            source,
            destination,
        }
    }

    // src -> dst and dst -> src
    pub fn reverse(self) -> Self {
        Self {
            protocol: self.protocol,
            source: self.destination,
            destination: self.source,
        }
    }
}

impl fmt::Display for FlowKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {} -> {}",
            self.protocol, self.source, self.destination
        )
    }
}

// firewall
pub struct Firewall {
    flow_timeout: Duration,
    allowed_replies: HashMap<FlowKey, Instant>,
}

impl Firewall {
    pub fn new(flow_timeout: Duration) -> Self {
        assert!(!flow_timeout.is_zero(), "flow timeout must be nonzero");

        Self {
            flow_timeout,
            allowed_replies: HashMap::new(),
        }
    }

    pub fn observe_outbound(&mut self, flow: FlowKey, now: Instant) {
        self.remove_expired(now);
        let expires_at = now
            .checked_add(self.flow_timeout) // checked add
            .expect("flow expiration is outside Instant's range");
        self.allowed_replies.insert(flow.reverse(), expires_at);
    }

    // check if the flow is allowed
    pub fn allow_inbound(&mut self, flow: FlowKey, now: Instant) -> bool {
        self.remove_expired(now);
        self.allowed_replies.contains_key(&flow)
    }

    // number of tracked reply flows
    pub fn tracked_reply_flows(&self) -> usize {
        self.allowed_replies.len()
    }

    // remove expired flows using a HashMap retain operation
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

    fn outbound_udp() -> FlowKey {
        FlowKey::new(TransportProtocol::Udp, CLIENT, SERVER)
    }

    #[test]
    fn unsolicited_inbound_flow_is_denied() {
        let now = Instant::now();
        let mut firewall = Firewall::new(Duration::from_secs(30));

        assert!(!firewall.allow_inbound(outbound_udp().reverse(), now));
    }

    #[test]
    fn outbound_flow_allows_its_exact_reply() {
        let now = Instant::now();
        let mut firewall = Firewall::new(Duration::from_secs(30));
        let outbound = outbound_udp();

        firewall.observe_outbound(outbound, now);

        assert!(firewall.allow_inbound(outbound.reverse(), now));
    }

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

    #[test]
    fn tcp_and_udp_flows_are_distinct() {
        let now = Instant::now();
        let mut firewall = Firewall::new(Duration::from_secs(30));
        let outbound = outbound_udp();
        let tcp_reply = FlowKey::new(TransportProtocol::Tcp, SERVER, CLIENT);

        firewall.observe_outbound(outbound, now);

        assert!(!firewall.allow_inbound(tcp_reply, now));
    }

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
