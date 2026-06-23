use std::net::Ipv4Addr;

use crate::auth::portal::{Ipv4Route, VpnConfigXml};
use crate::config::Config;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Linux,
    MacOs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPlan {
    pub actions: Vec<NetworkAction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkAction {
    DropWrongTunnelRoute {
        platform: Platform,
        endpoint: Ipv4Addr,
        interface: String,
    },
    ProtectTunnelRoute {
        platform: Platform,
        endpoint: Ipv4Addr,
    },
    RunCommand {
        program: String,
        args: Vec<String>,
    },
    ReplaceDefaultRoute {
        platform: Platform,
        interface: String,
    },
    ConfigureDns {
        platform: Platform,
        interface: String,
        servers: Vec<String>,
        search_domain: Option<String>,
    },
}

pub fn plan_network_actions(
    config: &Config,
    vpn_config: &VpnConfigXml,
    platform: Platform,
    interface: &str,
    tunnel_endpoint: Option<Ipv4Addr>,
) -> NetworkPlan {
    let mut actions = Vec::new();

    if config.set_routes {
        if let Some(endpoint) = tunnel_endpoint {
            actions.push(NetworkAction::DropWrongTunnelRoute {
                platform,
                endpoint,
                interface: interface.to_owned(),
            });
            actions.push(NetworkAction::ProtectTunnelRoute { platform, endpoint });
        }
        actions.extend(plan_routes(
            &vpn_config.split_routes,
            config.half_internet_routes,
            vpn_config.gateway.as_deref(),
            platform,
            interface,
        ));
    }

    if config.set_dns && (!vpn_config.dns_servers.is_empty() || vpn_config.dns_suffix.is_some()) {
        actions.push(NetworkAction::ConfigureDns {
            platform,
            interface: interface.to_owned(),
            servers: vpn_config.dns_servers.clone(),
            search_domain: vpn_config.dns_suffix.clone(),
        });
    }

    NetworkPlan { actions }
}

fn plan_routes(
    split_routes: &[Ipv4Route],
    half_internet_routes: bool,
    _gateway: Option<&str>,
    platform: Platform,
    interface: &str,
) -> Vec<NetworkAction> {
    if !split_routes.is_empty() {
        return split_routes
            .iter()
            .filter_map(|route| route_action(route, platform, interface))
            .collect();
    }

    if half_internet_routes {
        return vec![
            route_action_from_parts("0.0.0.0", "128.0.0.0", None, platform, interface),
            route_action_from_parts("128.0.0.0", "128.0.0.0", None, platform, interface),
        ];
    }

    vec![NetworkAction::ReplaceDefaultRoute {
        platform,
        interface: interface.to_owned(),
    }]
}

fn route_action(route: &Ipv4Route, platform: Platform, interface: &str) -> Option<NetworkAction> {
    let gateway = route.gateway.as_deref()?;
    Some(route_action_from_parts(
        &route.destination,
        &route.mask,
        Some(gateway),
        platform,
        interface,
    ))
}

fn route_action_from_parts(
    destination: &str,
    mask: &str,
    gateway: Option<&str>,
    platform: Platform,
    interface: &str,
) -> NetworkAction {
    match platform {
        Platform::Linux => {
            let destination = match ipv4_mask_to_prefix(mask) {
                Some(prefix) => format!("{destination}/{prefix}"),
                None => format!("{destination}/{mask}"),
            };
            let mut args = vec!["route".to_owned(), "add".to_owned(), destination];
            if let Some(gateway) = gateway {
                args.push("via".to_owned());
                args.push(gateway.to_owned());
            }
            args.push("dev".to_owned());
            args.push(interface.to_owned());
            NetworkAction::RunCommand {
                program: "ip".to_owned(),
                args,
            }
        }
        Platform::MacOs => {
            let mut args = vec![
                "add".to_owned(),
                "-net".to_owned(),
                destination.to_owned(),
                "-netmask".to_owned(),
                mask.to_owned(),
            ];
            if let Some(gateway) = gateway {
                args.push(gateway.to_owned());
            } else {
                args.push("-interface".to_owned());
                args.push(interface.to_owned());
            }
            NetworkAction::RunCommand {
                program: "/sbin/route".to_owned(),
                args,
            }
        }
    }
}

fn ipv4_mask_to_prefix(mask: &str) -> Option<u8> {
    let mut prefix = 0u8;
    let mut saw_zero = false;

    for octet in mask.split('.') {
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

    if mask.split('.').count() == 4 {
        Some(prefix)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vpn_config() -> VpnConfigXml {
        VpnConfigXml {
            raw_xml: String::new(),
            gateway: Some("10.212.134.200".to_owned()),
            assigned_ip: Some("10.212.134.200".to_owned()),
            dns_servers: vec!["10.0.0.10".to_owned(), "10.0.0.11".to_owned()],
            dns_suffix: Some("corp.example".to_owned()),
            split_routes: vec![Ipv4Route {
                destination: "10.10.0.0".to_owned(),
                mask: "255.255.0.0".to_owned(),
                gateway: Some("10.212.134.200".to_owned()),
            }],
        }
    }

    #[test]
    fn plans_linux_routes_and_dns() {
        let cfg = Config::default();
        let plan = plan_network_actions(&cfg, &vpn_config(), Platform::Linux, "ppp0", None);

        assert_eq!(
            plan.actions,
            vec![
                NetworkAction::RunCommand {
                    program: "ip".to_owned(),
                    args: vec![
                        "route".to_owned(),
                        "add".to_owned(),
                        "10.10.0.0/16".to_owned(),
                        "via".to_owned(),
                        "10.212.134.200".to_owned(),
                        "dev".to_owned(),
                        "ppp0".to_owned(),
                    ],
                },
                NetworkAction::ConfigureDns {
                    platform: Platform::Linux,
                    interface: "ppp0".to_owned(),
                    servers: vec!["10.0.0.10".to_owned(), "10.0.0.11".to_owned()],
                    search_domain: Some("corp.example".to_owned()),
                },
            ]
        );
    }

    #[test]
    fn plans_tunnel_endpoint_protection_before_routes() {
        let cfg = Config::default();
        let plan = plan_network_actions(
            &cfg,
            &vpn_config(),
            Platform::Linux,
            "ppp0",
            Some("203.0.113.10".parse().unwrap()),
        );

        assert_eq!(
            plan.actions[0],
            NetworkAction::DropWrongTunnelRoute {
                platform: Platform::Linux,
                endpoint: "203.0.113.10".parse().unwrap(),
                interface: "ppp0".to_owned(),
            }
        );
        assert_eq!(
            plan.actions[1],
            NetworkAction::ProtectTunnelRoute {
                platform: Platform::Linux,
                endpoint: "203.0.113.10".parse().unwrap(),
            }
        );
    }

    #[test]
    fn plans_macos_route_syntax() {
        let cfg = Config::default();
        let plan = plan_network_actions(&cfg, &vpn_config(), Platform::MacOs, "ppp0", None);

        assert_eq!(
            plan.actions[0],
            NetworkAction::RunCommand {
                program: "/sbin/route".to_owned(),
                args: vec![
                    "add".to_owned(),
                    "-net".to_owned(),
                    "10.10.0.0".to_owned(),
                    "-netmask".to_owned(),
                    "255.255.0.0".to_owned(),
                    "10.212.134.200".to_owned(),
                ],
            }
        );
    }

    #[test]
    fn respects_route_and_dns_switches() {
        let cfg = Config {
            set_routes: false,
            set_dns: false,
            ..Config::default()
        };
        let plan = plan_network_actions(&cfg, &vpn_config(), Platform::Linux, "ppp0", None);

        assert!(plan.actions.is_empty());
    }

    #[test]
    fn plans_half_internet_routes() {
        let cfg = Config {
            half_internet_routes: true,
            set_dns: false,
            ..Config::default()
        };
        let mut vpn = vpn_config();
        vpn.split_routes.clear();

        let plan = plan_network_actions(&cfg, &vpn, Platform::Linux, "ppp0", None);

        assert_eq!(plan.actions.len(), 2);
        assert_eq!(
            plan.actions[0],
            NetworkAction::RunCommand {
                program: "ip".to_owned(),
                args: vec![
                    "route".to_owned(),
                    "add".to_owned(),
                    "0.0.0.0/1".to_owned(),
                    "dev".to_owned(),
                    "ppp0".to_owned(),
                ],
            }
        );
    }

    #[test]
    fn plans_default_route_when_no_split_routes() {
        let cfg = Config {
            set_dns: false,
            ..Config::default()
        };
        let mut vpn = vpn_config();
        vpn.split_routes.clear();

        let plan = plan_network_actions(&cfg, &vpn, Platform::Linux, "ppp0", None);

        assert_eq!(
            plan.actions,
            vec![NetworkAction::ReplaceDefaultRoute {
                platform: Platform::Linux,
                interface: "ppp0".to_owned(),
            }]
        );
    }

    #[test]
    fn split_routes_take_precedence_over_half_internet_routes() {
        let cfg = Config {
            half_internet_routes: true,
            set_dns: false,
            ..Config::default()
        };
        let plan = plan_network_actions(&cfg, &vpn_config(), Platform::Linux, "ppp0", None);

        assert_eq!(plan.actions.len(), 1);
        assert!(matches!(plan.actions[0], NetworkAction::RunCommand { .. }));
    }

    #[test]
    fn rejects_non_contiguous_netmask_prefix_conversion() {
        assert_eq!(ipv4_mask_to_prefix("255.0.255.0"), None);
        assert_eq!(ipv4_mask_to_prefix("255.255.255.0"), Some(24));
    }
}
