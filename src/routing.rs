use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Ipv4Prefix {
    network: Ipv4Addr,
    length: u8,
}

impl Ipv4Prefix {
    pub fn contains(self, address: Ipv4Addr) -> bool {
        let mask = prefix_mask(self.length);
        u32::from(address) & mask == u32::from(self.network)
    }

    pub fn length(self) -> u8 {
        self.length
    }
}

impl fmt::Display for Ipv4Prefix {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.network, self.length)
    }
}

impl FromStr for Ipv4Prefix {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, length) = value
            .split_once('/')
            .ok_or_else(|| "prefix must be ADDRESS/LENGTH".to_string())?;
        let address: Ipv4Addr = address
            .parse()
            .map_err(|_| "prefix address must be IPv4".to_string())?;
        let length: u8 = length
            .parse()
            .map_err(|_| "prefix length must be an integer".to_string())?;
        if length > 32 {
            return Err("IPv4 prefix length must be between 0 and 32".into());
        }

        let network = Ipv4Addr::from(u32::from(address) & prefix_mask(length));
        if network != address {
            return Err(format!("prefix has host bits set; use {network}/{length}"));
        }
        Ok(Self { network, length })
    }
}

fn prefix_mask(length: u8) -> u32 {
    if length == 0 {
        0
    } else {
        u32::MAX << (32 - length)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SelectedRoute {
    pub prefix: Ipv4Prefix,
    pub node_id: String,
}

struct Advertisement {
    route: SelectedRoute,
    expires_at: Instant,
}

#[derive(Default)]
pub struct RouteRegistry {
    advertisements: Vec<Advertisement>,
}

impl RouteRegistry {
    pub fn advertise(&mut self, node_id: &str, prefix: Ipv4Prefix, lease: Duration, now: Instant) {
        self.remove_expired(now);

        let expires_at = now
            .checked_add(lease)
            .expect("route expiration is outside Instant's range");
        self.advertisements
            .retain(|entry| !(entry.route.node_id == node_id && entry.route.prefix == prefix));
        self.advertisements.push(Advertisement {
            route: SelectedRoute {
                prefix,
                node_id: node_id.to_string(),
            },
            expires_at,
        });
    }

    pub fn lookup(&mut self, destination: Ipv4Addr, now: Instant) -> Option<SelectedRoute> {
        self.remove_expired(now);
        self.advertisements
            .iter()
            .filter(|entry| entry.route.prefix.contains(destination))
            .max_by_key(|entry| entry.route.prefix.length())
            .map(|entry| entry.route.clone())
    }

    fn remove_expired(&mut self, now: Instant) {
        self.advertisements
            .retain(|advertisement| advertisement.expires_at > now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_rejects_noncanonical_host_bits() {
        assert_eq!(
            "10.30.0.7/24".parse::<Ipv4Prefix>(),
            Err("prefix has host bits set; use 10.30.0.0/24".into())
        );
    }

    #[test]
    fn longest_matching_prefix_selects_the_most_specific_peer() {
        let now = Instant::now();
        let broad = "10.0.0.0/8".parse().unwrap();
        let specific = "10.30.0.0/24".parse().unwrap();
        let mut registry = RouteRegistry::default();
        registry.advertise("mesh-c", broad, Duration::from_secs(30), now);
        registry.advertise("mesh-b", specific, Duration::from_secs(30), now);

        assert_eq!(
            registry.lookup(Ipv4Addr::new(10, 30, 0, 2), now),
            Some(SelectedRoute {
                prefix: specific,
                node_id: "mesh-b".into(),
            })
        );
    }

    #[test]
    fn expired_advertisement_is_not_selected() {
        let now = Instant::now();
        let prefix = "10.30.0.0/24".parse().unwrap();
        let mut registry = RouteRegistry::default();
        registry.advertise("mesh-b", prefix, Duration::from_secs(30), now);

        assert_eq!(
            registry.lookup(Ipv4Addr::new(10, 30, 0, 2), now + Duration::from_secs(30)),
            None
        );
    }
}
