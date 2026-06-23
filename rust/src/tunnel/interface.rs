use std::net::Ipv4Addr;
use std::thread::sleep;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PppInterface {
    pub name: String,
    pub address: Ipv4Addr,
}

pub fn wait_for_up_ppp_interface(
    expected_addr: Ipv4Addr,
    preferred_name: Option<&str>,
    timeout: Duration,
    interval: Duration,
) -> std::io::Result<Option<PppInterface>> {
    let start = Instant::now();
    loop {
        if let Some(interface) = find_up_ppp_interface(expected_addr, preferred_name)? {
            return Ok(Some(interface));
        }
        if start.elapsed() >= timeout {
            return Ok(None);
        }
        sleep(interval);
    }
}

#[cfg(unix)]
pub fn find_up_ppp_interface(
    expected_addr: Ipv4Addr,
    preferred_name: Option<&str>,
) -> std::io::Result<Option<PppInterface>> {
    use nix::ifaddrs::getifaddrs;
    use nix::net::if_::InterfaceFlags;

    let addrs = getifaddrs().map_err(std::io::Error::other)?;
    for iface in addrs {
        if !iface.flags.contains(InterfaceFlags::IFF_UP) {
            continue;
        }
        if !matches_interface_name(&iface.interface_name, preferred_name) {
            continue;
        }

        let Some(address) = iface.address else {
            continue;
        };
        let Some(sockaddr) = address.as_sockaddr_in() else {
            continue;
        };
        let addr = sockaddr.ip();
        if addr == expected_addr {
            return Ok(Some(PppInterface {
                name: iface.interface_name,
                address: addr,
            }));
        }
    }

    Ok(None)
}

#[cfg(not(unix))]
pub fn find_up_ppp_interface(
    _expected_addr: Ipv4Addr,
    _preferred_name: Option<&str>,
) -> std::io::Result<Option<PppInterface>> {
    Ok(None)
}

fn matches_interface_name(name: &str, preferred_name: Option<&str>) -> bool {
    if let Some(preferred_name) = preferred_name {
        if !preferred_name.is_empty() && name.contains(preferred_name) {
            return true;
        }
    }
    name.contains("ppp")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_ppp_or_preferred_interface_names() {
        assert!(matches_interface_name("ppp0", None));
        assert!(matches_interface_name("ppp0", Some("vpn0")));
        assert!(matches_interface_name("utun12", Some("utun12")));
        assert!(matches_interface_name("vpn-ppp", None));
        assert!(!matches_interface_name("en0", None));
        assert!(!matches_interface_name("en0", Some("utun")));
    }
}
