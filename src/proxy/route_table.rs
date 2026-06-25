use std::net::Ipv4Addr;

use crate::auth::portal::VpnConfigXml;
use crate::config::Config;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyRouteTable {
    routes: Vec<Ipv4Net>,
}

impl ProxyRouteTable {
    pub fn from_config(config: &Config, vpn_config: &VpnConfigXml) -> Self {
        if !config.set_routes {
            return Self { routes: Vec::new() };
        }

        let mut routes = Vec::new();
        if !vpn_config.split_routes.is_empty() {
            for route in &vpn_config.split_routes {
                if let Some(net) = Ipv4Net::from_addr_and_mask(&route.destination, &route.mask) {
                    routes.push(net);
                }
            }
        } else if config.half_internet_routes {
            routes.push(Ipv4Net::new(Ipv4Addr::new(0, 0, 0, 0), 1));
            routes.push(Ipv4Net::new(Ipv4Addr::new(128, 0, 0, 0), 1));
        } else {
            routes.push(Ipv4Net::new(Ipv4Addr::new(0, 0, 0, 0), 0));
        }

        Self { routes }
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    pub fn can_route(&self, destination: Ipv4Addr) -> bool {
        self.routes.iter().any(|route| route.contains(destination))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Net {
    network: Ipv4Addr,
    prefix: u8,
}

impl Ipv4Net {
    pub fn new(network: Ipv4Addr, prefix: u8) -> Self {
        let prefix = prefix.min(32);
        let mask = prefix_mask(prefix);
        Self {
            network: Ipv4Addr::from(u32::from(network) & mask),
            prefix,
        }
    }

    pub fn from_addr_and_mask(addr: &str, mask: &str) -> Option<Self> {
        let addr = addr.parse().ok()?;
        let prefix = ipv4_mask_to_prefix(mask)?;
        Some(Self::new(addr, prefix))
    }

    pub fn contains(&self, addr: Ipv4Addr) -> bool {
        let mask = prefix_mask(self.prefix);
        (u32::from(addr) & mask) == u32::from(self.network)
    }
}

fn prefix_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn ipv4_mask_to_prefix(mask: &str) -> Option<u8> {
    let mut prefix = 0u8;
    let mut saw_zero = false;
    let mut octets = 0;

    for octet in mask.split('.') {
        octets += 1;
        let octet = octet.parse::<u8>().ok()?;
        for bit in (0..8).rev() {
            let is_one = (octet & (1 << bit)) != 0;
            if is_one {
                if saw_zero {
                    return None;
                }
                prefix += 1;
            } else {
                saw_zero = true;
            }
        }
    }

    if octets == 4 {
        Some(prefix)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::portal::Ipv4Route;

    fn vpn_config_with_routes(routes: Vec<Ipv4Route>) -> VpnConfigXml {
        VpnConfigXml {
            raw_xml: String::new(),
            gateway: Some("10.212.134.200".to_owned()),
            assigned_ip: Some("10.212.134.200".to_owned()),
            dns_servers: vec!["10.0.0.10".to_owned()],
            dns_suffix: Some("corp.example".to_owned()),
            split_routes: routes,
        }
    }

    #[test]
    fn split_routes_allow_only_matching_destinations() {
        let cfg = Config::default();
        let vpn = vpn_config_with_routes(vec![Ipv4Route {
            destination: "10.10.0.0".to_owned(),
            mask: "255.255.0.0".to_owned(),
            gateway: Some("10.212.134.200".to_owned()),
        }]);

        let table = ProxyRouteTable::from_config(&cfg, &vpn);

        assert!(table.can_route("10.10.25.1".parse().unwrap()));
        assert!(!table.can_route("10.11.25.1".parse().unwrap()));
    }

    #[test]
    fn default_route_allows_any_destination_when_no_split_routes() {
        let cfg = Config::default();
        let vpn = vpn_config_with_routes(Vec::new());

        let table = ProxyRouteTable::from_config(&cfg, &vpn);

        assert!(table.can_route("10.10.25.1".parse().unwrap()));
        assert!(table.can_route("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn half_internet_routes_cover_full_ipv4_space() {
        let cfg = Config {
            half_internet_routes: true,
            ..Config::default()
        };
        let vpn = vpn_config_with_routes(Vec::new());

        let table = ProxyRouteTable::from_config(&cfg, &vpn);

        assert!(table.can_route("10.10.25.1".parse().unwrap()));
        assert!(table.can_route("200.1.2.3".parse().unwrap()));
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn no_routes_disables_proxy_routing() {
        let cfg = Config {
            set_routes: false,
            ..Config::default()
        };
        let vpn = vpn_config_with_routes(Vec::new());

        let table = ProxyRouteTable::from_config(&cfg, &vpn);

        assert!(table.is_empty());
        assert!(!table.can_route("10.10.25.1".parse().unwrap()));
    }
}
