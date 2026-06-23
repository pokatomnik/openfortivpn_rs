use std::env;
use std::fs;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::error::{OpenfortivpnError, Result};
use crate::logger;
use crate::net_plan::{NetworkAction, NetworkPlan, Platform};

const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";
const RESOLVCONF_CANDIDATES: &[&str] = &["/sbin/resolvconf", "/usr/sbin/resolvconf", "resolvconf"];
const SCUTIL_CANDIDATES: &[&str] = &["/usr/sbin/scutil", "/usr/bin/scutil", "scutil"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyOptions {
    pub use_resolvconf: bool,
}

impl Default for ApplyOptions {
    fn default() -> Self {
        Self {
            use_resolvconf: true,
        }
    }
}

#[derive(Debug, Default)]
pub struct AppliedNetworkPlan {
    applied: Vec<AppliedNetworkAction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AppliedNetworkAction {
    ProtectedTunnelRoute {
        program: String,
        rollback_args: Vec<String>,
    },
    Command {
        program: String,
        rollback_args: Vec<String>,
    },
    DefaultRoute {
        platform: Platform,
        interface: String,
        restore: Option<(String, Vec<String>)>,
    },
    Resolvconf {
        program: String,
        interface: String,
    },
    MacOsScutilDns {
        program: String,
        key: String,
    },
    ResolvConfFile {
        added_lines: Vec<String>,
    },
}

impl AppliedNetworkPlan {
    pub fn is_empty(&self) -> bool {
        self.applied.is_empty()
    }

    pub fn rollback(mut self) -> Result<()> {
        let mut first_error = None;
        while let Some(action) = self.applied.pop() {
            let result = match action {
                AppliedNetworkAction::ProtectedTunnelRoute {
                    program,
                    rollback_args,
                } => run_command(&program, &rollback_args),
                AppliedNetworkAction::Command {
                    program,
                    rollback_args,
                } => run_command(&program, &rollback_args),
                AppliedNetworkAction::DefaultRoute {
                    platform,
                    interface,
                    restore,
                } => rollback_default_route(platform, &interface, restore),
                AppliedNetworkAction::Resolvconf { program, interface } => {
                    let args = vec!["-d".to_owned(), format!("{interface}.openfortivpn")];
                    run_command(&program, &args)
                }
                AppliedNetworkAction::MacOsScutilDns { program, key } => run_command_with_stdin(
                    &program,
                    &[],
                    build_macos_scutil_remove_script(&key).as_bytes(),
                ),
                AppliedNetworkAction::ResolvConfFile { added_lines } => {
                    let current = fs::read(RESOLV_CONF_PATH)?;
                    let restored = remove_added_dns_lines(&current, &added_lines);
                    fs::write(RESOLV_CONF_PATH, restored).map_err(Into::into)
                }
            };

            if let Err(err) = result {
                if first_error.is_none() {
                    first_error = Some(err);
                }
            }
        }

        if let Some(err) = first_error {
            Err(err)
        } else {
            Ok(())
        }
    }
}

pub fn apply_network_plan(
    plan: &NetworkPlan,
    options: &ApplyOptions,
) -> Result<AppliedNetworkPlan> {
    let mut applied = AppliedNetworkPlan::default();

    for action in &plan.actions {
        let result = match action {
            NetworkAction::DropWrongTunnelRoute {
                platform,
                endpoint,
                interface,
            } => {
                drop_wrong_tunnel_route(*platform, *endpoint, interface);
                Ok(())
            }
            NetworkAction::ProtectTunnelRoute { platform, endpoint } => {
                protect_tunnel_route(*platform, *endpoint, &mut applied)
            }
            NetworkAction::RunCommand { program, args } => {
                run_command(program, args)?;
                if let Some(rollback_args) = rollback_args_for_command(program, args) {
                    applied.applied.push(AppliedNetworkAction::Command {
                        program: program.clone(),
                        rollback_args,
                    });
                }
                Ok(())
            }
            NetworkAction::ReplaceDefaultRoute {
                platform,
                interface,
            } => apply_default_route(*platform, interface, &mut applied),
            NetworkAction::ConfigureDns {
                platform,
                interface,
                servers,
                search_domain,
            } => apply_dns(
                *platform,
                interface,
                servers,
                search_domain.as_deref(),
                options,
                &mut applied,
            ),
        };

        if let Err(err) = result {
            if let Err(rollback_err) = applied.rollback() {
                return Err(OpenfortivpnError::Network(format!(
                    "{err}; rollback also failed: {rollback_err}"
                )));
            }
            return Err(err);
        }
    }

    Ok(applied)
}

fn drop_wrong_tunnel_route(platform: Platform, endpoint: Ipv4Addr, interface: &str) {
    let result = match platform {
        Platform::Linux => drop_wrong_linux_tunnel_route(endpoint, interface),
        Platform::MacOs => drop_wrong_macos_tunnel_route(endpoint, interface),
    };

    if let Err(err) = result {
        logger::warn(&format!(
            "issue while checking/removing wrong route to VPN endpoint: {err}"
        ));
    }
}

fn drop_wrong_linux_tunnel_route(endpoint: Ipv4Addr, interface: &str) -> Result<()> {
    let destination = format!("{endpoint}/32");
    let output = Command::new("ip")
        .args(["route", "show", destination.as_str(), "dev", interface])
        .output()?;
    if !output.status.success() || output.stdout.is_empty() {
        return Ok(());
    }

    logger::warn(&format!(
        "removing wrong route to VPN endpoint {endpoint} via {interface}"
    ));
    let args = vec![
        "route".to_owned(),
        "del".to_owned(),
        destination,
        "dev".to_owned(),
        interface.to_owned(),
    ];
    run_command("ip", &args)
}

fn drop_wrong_macos_tunnel_route(endpoint: Ipv4Addr, interface: &str) -> Result<()> {
    let endpoint = endpoint.to_string();
    let output = Command::new("/sbin/route")
        .args(["-n", "get", endpoint.as_str()])
        .output()?;
    if !output.status.success() {
        return Ok(());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if macos_route_value(&stdout, "interface:") != Some(interface) {
        return Ok(());
    }

    logger::warn(&format!(
        "removing wrong route to VPN endpoint {endpoint} via {interface}"
    ));
    let args = vec!["delete".to_owned(), "-host".to_owned(), endpoint];
    run_command("/sbin/route", &args)
}

fn protect_tunnel_route(
    platform: Platform,
    endpoint: Ipv4Addr,
    applied: &mut AppliedNetworkPlan,
) -> Result<()> {
    let Some((program, args, rollback_args)) =
        build_protect_tunnel_route_commands(platform, endpoint)?
    else {
        return Ok(());
    };

    if !run_command_ignore_existing_route(&program, &args)? {
        return Ok(());
    }
    applied
        .applied
        .push(AppliedNetworkAction::ProtectedTunnelRoute {
            program,
            rollback_args,
        });
    Ok(())
}

fn build_protect_tunnel_route_commands(
    platform: Platform,
    endpoint: Ipv4Addr,
) -> Result<Option<(String, Vec<String>, Vec<String>)>> {
    match platform {
        Platform::Linux => build_linux_protect_tunnel_route_commands(endpoint),
        Platform::MacOs => build_macos_protect_tunnel_route_commands(endpoint),
    }
}

fn build_linux_protect_tunnel_route_commands(
    endpoint: Ipv4Addr,
) -> Result<Option<(String, Vec<String>, Vec<String>)>> {
    let endpoint = endpoint.to_string();
    let output = Command::new("ip")
        .args(["route", "get", endpoint.as_str()])
        .output()?;
    if !output.status.success() {
        return Ok(None);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(
        parse_linux_route_get_for_host_route(&stdout, &endpoint).map(|args| {
            let rollback = vec![
                "route".to_owned(),
                "del".to_owned(),
                format!("{endpoint}/32"),
            ];
            ("ip".to_owned(), args, rollback)
        }),
    )
}

fn build_macos_protect_tunnel_route_commands(
    endpoint: Ipv4Addr,
) -> Result<Option<(String, Vec<String>, Vec<String>)>> {
    let endpoint = endpoint.to_string();
    let output = Command::new("/sbin/route")
        .args(["-n", "get", endpoint.as_str()])
        .output()?;
    if !output.status.success() {
        return Ok(None);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(
        parse_macos_route_get_for_host_route(&stdout, &endpoint).map(|args| {
            let rollback = vec!["delete".to_owned(), "-host".to_owned(), endpoint];
            ("/sbin/route".to_owned(), args, rollback)
        }),
    )
}

fn parse_linux_route_get_for_host_route(output: &str, endpoint: &str) -> Option<Vec<String>> {
    let line = output.lines().next()?.trim();
    if line.is_empty() || line.contains(" dev ppp") {
        return None;
    }

    let tokens = line.split_whitespace().collect::<Vec<_>>();
    let via = token_after(&tokens, "via");
    let dev = token_after(&tokens, "dev")?;
    let mut args = vec![
        "route".to_owned(),
        "add".to_owned(),
        format!("{endpoint}/32"),
    ];
    if let Some(via) = via {
        args.push("via".to_owned());
        args.push(via.to_owned());
    }
    args.push("dev".to_owned());
    args.push(dev.to_owned());
    Some(args)
}

fn parse_macos_route_get_for_host_route(output: &str, endpoint: &str) -> Option<Vec<String>> {
    let gateway = macos_route_value(output, "gateway:");
    let interface = macos_route_value(output, "interface:")?;
    if interface.starts_with("ppp") {
        return None;
    }

    let mut args = vec!["add".to_owned(), "-host".to_owned(), endpoint.to_owned()];
    if let Some(gateway) = gateway.filter(|value| !value.is_empty()) {
        args.push(gateway.to_owned());
    } else {
        args.push("-interface".to_owned());
        args.push(interface.to_owned());
    }
    Some(args)
}

fn token_after<'a>(tokens: &'a [&str], needle: &str) -> Option<&'a str> {
    tokens
        .windows(2)
        .find_map(|window| (window[0] == needle).then_some(window[1]))
}

fn macos_route_value<'a>(output: &'a str, key: &str) -> Option<&'a str> {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix(key).map(str::trim))
}

fn apply_default_route(
    platform: Platform,
    interface: &str,
    applied: &mut AppliedNetworkPlan,
) -> Result<()> {
    let restore = capture_default_route(platform)?;
    delete_default_route(platform, interface);
    if let Err(err) = add_default_route(platform, interface) {
        if let Some((program, args)) = &restore {
            if let Err(restore_err) = run_command(program, args) {
                return Err(OpenfortivpnError::Network(format!(
                    "{err}; failed to restore previous default route: {restore_err}"
                )));
            }
        }
        return Err(err);
    }
    applied.applied.push(AppliedNetworkAction::DefaultRoute {
        platform,
        interface: interface.to_owned(),
        restore,
    });
    Ok(())
}

fn rollback_default_route(
    platform: Platform,
    interface: &str,
    restore: Option<(String, Vec<String>)>,
) -> Result<()> {
    delete_default_route(platform, interface);
    if let Some((program, args)) = restore {
        run_command(&program, &args)?;
    }
    Ok(())
}

fn capture_default_route(platform: Platform) -> Result<Option<(String, Vec<String>)>> {
    match platform {
        Platform::Linux => capture_linux_default_route(),
        Platform::MacOs => capture_macos_default_route(),
    }
}

fn capture_linux_default_route() -> Result<Option<(String, Vec<String>)>> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()?;
    if !output.status.success() {
        return Ok(None);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_linux_default_route(&stdout).map(|args| ("ip".to_owned(), args)))
}

fn capture_macos_default_route() -> Result<Option<(String, Vec<String>)>> {
    let output = Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .output()?;
    if !output.status.success() {
        return Ok(None);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_macos_default_route(&stdout).map(|args| ("/sbin/route".to_owned(), args)))
}

fn parse_linux_default_route(output: &str) -> Option<Vec<String>> {
    let line = output.lines().next()?.trim();
    if line.is_empty() {
        return None;
    }
    let mut args = vec!["route".to_owned(), "add".to_owned()];
    args.extend(line.split_whitespace().map(str::to_owned));
    Some(args)
}

fn parse_macos_default_route(output: &str) -> Option<Vec<String>> {
    let gateway = output.lines().find_map(|line| {
        let line = line.trim();
        line.strip_prefix("gateway:").map(str::trim)
    })?;
    if gateway.is_empty() {
        return None;
    }
    Some(vec![
        "add".to_owned(),
        "default".to_owned(),
        gateway.to_owned(),
    ])
}

fn delete_default_route(platform: Platform, interface: &str) {
    let result = match platform {
        Platform::Linux => run_command(
            "ip",
            &[
                "route".to_owned(),
                "del".to_owned(),
                "default".to_owned(),
                "dev".to_owned(),
                interface.to_owned(),
            ],
        )
        .or_else(|_| {
            run_command(
                "ip",
                &["route".to_owned(), "del".to_owned(), "default".to_owned()],
            )
        }),
        Platform::MacOs => run_command(
            "/sbin/route",
            &[
                "delete".to_owned(),
                "default".to_owned(),
                "-interface".to_owned(),
                interface.to_owned(),
            ],
        )
        .or_else(|_| run_command("/sbin/route", &["delete".to_owned(), "default".to_owned()])),
    };
    if let Err(err) = result {
        logger::warn(&format!("could not delete current default route: {err}"));
    }
}

fn add_default_route(platform: Platform, interface: &str) -> Result<()> {
    match platform {
        Platform::Linux => run_command(
            "ip",
            &[
                "route".to_owned(),
                "add".to_owned(),
                "default".to_owned(),
                "dev".to_owned(),
                interface.to_owned(),
            ],
        ),
        Platform::MacOs => run_command(
            "/sbin/route",
            &[
                "add".to_owned(),
                "default".to_owned(),
                "-interface".to_owned(),
                interface.to_owned(),
            ],
        ),
    }
}

fn apply_dns(
    platform: Platform,
    interface: &str,
    servers: &[String],
    search_domain: Option<&str>,
    options: &ApplyOptions,
    applied: &mut AppliedNetworkPlan,
) -> Result<()> {
    if servers.is_empty() && search_domain.is_none() {
        return Ok(());
    }

    if platform == Platform::MacOs
        && apply_macos_scutil_dns(interface, servers, search_domain, applied)?
    {
        return Ok(());
    }

    let resolv_body = build_resolvconf_body(servers, search_domain);
    if options.use_resolvconf {
        if let Some(program) = find_resolvconf() {
            run_command_with_stdin(
                &program,
                &["-a".to_owned(), format!("{interface}.openfortivpn")],
                resolv_body.as_bytes(),
            )?;
            applied.applied.push(AppliedNetworkAction::Resolvconf {
                program,
                interface: interface.to_owned(),
            });
            return Ok(());
        }
    }

    let original_contents = fs::read(RESOLV_CONF_PATH)?;
    let added_lines = dns_lines_to_add(&original_contents, servers, search_domain);
    if added_lines.is_empty() {
        return Ok(());
    }
    let new_contents = prepend_dns_lines_to_resolv_conf(&original_contents, &added_lines);
    fs::write(RESOLV_CONF_PATH, new_contents)?;
    applied
        .applied
        .push(AppliedNetworkAction::ResolvConfFile { added_lines });
    Ok(())
}

fn run_command_ignore_existing_route(program: &str, args: &[String]) -> Result<bool> {
    let output = Command::new(program).args(args).output()?;
    if output.status.success() {
        return Ok(true);
    }

    if command_output_mentions_existing_route(&output.stdout, &output.stderr) {
        logger::warn(&format!(
            "route already exists, leaving it unchanged: {} {}",
            program,
            args.join(" ")
        ));
        return Ok(false);
    }

    Err(command_error(
        program,
        args,
        &output.stdout,
        &output.stderr,
        output.status.to_string(),
    ))
}

fn command_output_mentions_existing_route(stdout: &[u8], stderr: &[u8]) -> bool {
    let mut text = String::new();
    text.push_str(&String::from_utf8_lossy(stdout).to_ascii_lowercase());
    text.push_str(&String::from_utf8_lossy(stderr).to_ascii_lowercase());
    text.contains("file exists") || text.contains("route already exists")
}

fn run_command(program: &str, args: &[String]) -> Result<()> {
    let output = Command::new(program).args(args).output()?;
    if output.status.success() {
        return Ok(());
    }

    Err(command_error(
        program,
        args,
        &output.stdout,
        &output.stderr,
        output.status.to_string(),
    ))
}

fn run_command_with_stdin(program: &str, args: &[String], stdin: &[u8]) -> Result<()> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .as_mut()
        .ok_or_else(|| OpenfortivpnError::Network("failed to open command stdin".to_owned()))?
        .write_all(stdin)?;
    let output = child.wait_with_output()?;
    if output.status.success() {
        return Ok(());
    }

    Err(command_error(
        program,
        args,
        &output.stdout,
        &output.stderr,
        output.status.to_string(),
    ))
}

fn command_error(
    program: &str,
    args: &[String],
    stdout: &[u8],
    stderr: &[u8],
    status: String,
) -> OpenfortivpnError {
    let stderr = String::from_utf8_lossy(stderr).trim().to_owned();
    let stdout = String::from_utf8_lossy(stdout).trim().to_owned();
    let detail = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        status
    };

    OpenfortivpnError::Network(format!(
        "command failed: {} {}: {}",
        program,
        args.join(" "),
        detail
    ))
}

fn rollback_args_for_command(program: &str, args: &[String]) -> Option<Vec<String>> {
    if program == "ip" && args.len() >= 3 && args[0] == "route" && args[1] == "add" {
        let mut rollback = args.to_vec();
        rollback[1] = "del".to_owned();
        return Some(rollback);
    }

    if program.ends_with("route") && !args.is_empty() && args[0] == "add" {
        let mut rollback = args.to_vec();
        rollback[0] = "delete".to_owned();
        return Some(rollback);
    }

    None
}

fn apply_macos_scutil_dns(
    interface: &str,
    servers: &[String],
    search_domain: Option<&str>,
    applied: &mut AppliedNetworkPlan,
) -> Result<bool> {
    let Some(program) = find_scutil() else {
        return Ok(false);
    };
    let key = macos_scutil_dns_key(interface);
    let script = build_macos_scutil_dns_script(&key, interface, servers, search_domain);
    if let Err(err) = run_command_with_stdin(&program, &[], script.as_bytes()) {
        logger::warn(&format!(
            "could not configure macOS DNS with scutil, falling back to resolv.conf/resolvconf: {err}"
        ));
        return Ok(false);
    }
    applied
        .applied
        .push(AppliedNetworkAction::MacOsScutilDns { program, key });
    Ok(true)
}

fn find_resolvconf() -> Option<String> {
    find_program_from_candidates(RESOLVCONF_CANDIDATES)
}

fn find_scutil() -> Option<String> {
    find_program_from_candidates(SCUTIL_CANDIDATES)
}

fn find_program_from_candidates(candidates: &[&str]) -> Option<String> {
    candidates.iter().find_map(|candidate| {
        if candidate.contains('/') {
            Path::new(candidate)
                .exists()
                .then(|| (*candidate).to_owned())
        } else {
            find_program_in_path(candidate).map(|path| path.to_string_lossy().into_owned())
        }
    })
}

fn macos_scutil_dns_key(interface: &str) -> String {
    format!(
        "State:/Network/Service/openfortivpn-{}/DNS",
        sanitize_scutil_key_component(interface)
    )
}

fn sanitize_scutil_key_component(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    if sanitized.is_empty() {
        "vpn".to_owned()
    } else {
        sanitized
    }
}

fn build_macos_scutil_dns_script(
    key: &str,
    interface: &str,
    servers: &[String],
    search_domain: Option<&str>,
) -> String {
    let mut script = String::new();
    script.push_str("d.init\n");
    script.push_str("d.add InterfaceName ");
    script.push_str(&scutil_value(interface));
    script.push('\n');
    if !servers.is_empty() {
        script.push_str("d.add ServerAddresses *");
        for server in servers {
            script.push(' ');
            script.push_str(&scutil_value(server));
        }
        script.push('\n');
    }
    let search_domains = split_dns_search_domains(search_domain);
    if !search_domains.is_empty() {
        script.push_str("d.add SearchDomains *");
        for domain in &search_domains {
            script.push(' ');
            script.push_str(&scutil_value(domain));
        }
        script.push('\n');
        script.push_str("d.add SupplementalMatchDomains *");
        for domain in &search_domains {
            script.push(' ');
            script.push_str(&scutil_value(domain));
        }
        script.push('\n');
    }
    script.push_str("set ");
    script.push_str(key);
    script.push('\n');
    script
}

fn build_macos_scutil_remove_script(key: &str) -> String {
    format!("remove {key}\n")
}

fn split_dns_search_domains(search_domain: Option<&str>) -> Vec<String> {
    search_domain
        .unwrap_or_default()
        .split([';', ' ', '\t'])
        .filter(|part| !part.is_empty())
        .map(str::to_owned)
        .collect()
}

fn scutil_value(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_' | ':' | '/'))
    {
        value.to_owned()
    } else {
        let mut quoted = String::from("\"");
        for ch in value.chars() {
            if matches!(ch, '\\' | '"') {
                quoted.push('\\');
            }
            quoted.push(ch);
        }
        quoted.push('"');
        quoted
    }
}

fn find_program_in_path(program: &str) -> Option<PathBuf> {
    let paths = env::var_os("PATH")?;
    env::split_paths(&paths)
        .map(|dir| dir.join(program))
        .find(|candidate| candidate.is_file())
}

fn build_resolvconf_body(servers: &[String], search_domain: Option<&str>) -> String {
    let mut out = String::new();
    for server in servers {
        out.push_str("nameserver ");
        out.push_str(server);
        out.push('\n');
    }
    if let Some(search_domain) = search_domain.filter(|value| !value.is_empty()) {
        out.push_str("search ");
        out.push_str(&search_domain.replace(';', " "));
        out.push('\n');
    }
    out
}

fn dns_lines_to_add(
    original: &[u8],
    servers: &[String],
    search_domain: Option<&str>,
) -> Vec<String> {
    let original_text = String::from_utf8_lossy(original);
    build_dns_lines(servers, search_domain)
        .into_iter()
        .filter(|line| !original_text.lines().any(|existing| existing == line))
        .collect()
}

fn build_dns_lines(servers: &[String], search_domain: Option<&str>) -> Vec<String> {
    let mut lines = servers
        .iter()
        .map(|server| format!("nameserver {server}"))
        .collect::<Vec<_>>();
    if let Some(search_domain) = search_domain.filter(|value| !value.is_empty()) {
        lines.push(format!("search {}", search_domain.replace(';', " ")));
    }
    lines
}

fn prepend_dns_lines_to_resolv_conf(original: &[u8], added_lines: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for line in added_lines {
        out.extend_from_slice(line.as_bytes());
        out.push(b'\n');
    }
    out.extend_from_slice(original);
    out
}

#[cfg(test)]
fn prepend_vpn_dns_to_resolv_conf(
    original: &[u8],
    servers: &[String],
    search_domain: Option<&str>,
) -> Vec<u8> {
    let added_lines = dns_lines_to_add(original, servers, search_domain);
    prepend_dns_lines_to_resolv_conf(original, &added_lines)
}

fn remove_added_dns_lines(current: &[u8], added_lines: &[String]) -> Vec<u8> {
    let mut pending = added_lines.to_vec();
    let text = String::from_utf8_lossy(current);
    let mut out = String::new();

    for line in text.lines() {
        if let Some(pos) = pending.iter().position(|added| added == line) {
            pending.remove(pos);
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }

    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_route_get_for_tunnel_route_protection() {
        assert_eq!(
            parse_linux_route_get_for_host_route(
                "203.0.113.10 via 192.0.2.1 dev en0 src 192.0.2.55 uid 0\n",
                "203.0.113.10"
            ),
            Some(vec![
                "route".to_owned(),
                "add".to_owned(),
                "203.0.113.10/32".to_owned(),
                "via".to_owned(),
                "192.0.2.1".to_owned(),
                "dev".to_owned(),
                "en0".to_owned(),
            ])
        );
        assert_eq!(
            parse_linux_route_get_for_host_route(
                "203.0.113.10 dev ppp0 src 10.0.0.2 uid 0\n",
                "203.0.113.10"
            ),
            None
        );
    }

    #[test]
    fn parses_macos_route_get_for_tunnel_route_protection() {
        assert_eq!(
            parse_macos_route_get_for_host_route(
                "   route to: 203.0.113.10\ndestination: default\n    gateway: 192.0.2.1\n  interface: en0\n",
                "203.0.113.10"
            ),
            Some(vec![
                "add".to_owned(),
                "-host".to_owned(),
                "203.0.113.10".to_owned(),
                "192.0.2.1".to_owned(),
            ])
        );
        assert_eq!(
            parse_macos_route_get_for_host_route(
                "   route to: 203.0.113.10\n  interface: ppp0\n",
                "203.0.113.10"
            ),
            None
        );
    }

    #[test]
    fn parses_linux_default_route_for_restore() {
        assert_eq!(
            parse_linux_default_route("default via 192.0.2.1 dev en0 proto dhcp\n"),
            Some(vec![
                "route".to_owned(),
                "add".to_owned(),
                "default".to_owned(),
                "via".to_owned(),
                "192.0.2.1".to_owned(),
                "dev".to_owned(),
                "en0".to_owned(),
                "proto".to_owned(),
                "dhcp".to_owned(),
            ])
        );
        assert_eq!(parse_linux_default_route(""), None);
    }

    #[test]
    fn parses_macos_default_route_for_restore() {
        assert_eq!(
            parse_macos_default_route(
                "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.0.2.1\n  interface: en0\n"
            ),
            Some(vec![
                "add".to_owned(),
                "default".to_owned(),
                "192.0.2.1".to_owned(),
            ])
        );
        assert_eq!(parse_macos_default_route("route to: default\n"), None);
    }

    #[test]
    fn builds_linux_route_rollback_command() {
        let args = vec![
            "route".to_owned(),
            "add".to_owned(),
            "10.10.0.0/16".to_owned(),
            "via".to_owned(),
            "10.212.134.200".to_owned(),
            "dev".to_owned(),
            "ppp0".to_owned(),
        ];

        assert_eq!(
            rollback_args_for_command("ip", &args),
            Some(vec![
                "route".to_owned(),
                "del".to_owned(),
                "10.10.0.0/16".to_owned(),
                "via".to_owned(),
                "10.212.134.200".to_owned(),
                "dev".to_owned(),
                "ppp0".to_owned(),
            ])
        );
    }

    #[test]
    fn builds_macos_route_rollback_command() {
        let args = vec![
            "add".to_owned(),
            "-net".to_owned(),
            "10.10.0.0".to_owned(),
            "-netmask".to_owned(),
            "255.255.0.0".to_owned(),
            "10.212.134.200".to_owned(),
        ];

        assert_eq!(
            rollback_args_for_command("/sbin/route", &args),
            Some(vec![
                "delete".to_owned(),
                "-net".to_owned(),
                "10.10.0.0".to_owned(),
                "-netmask".to_owned(),
                "255.255.0.0".to_owned(),
                "10.212.134.200".to_owned(),
            ])
        );
    }

    #[test]
    fn leaves_unknown_commands_without_rollback() {
        assert_eq!(
            rollback_args_for_command("echo", &["hello".to_owned()]),
            None
        );
    }

    #[test]
    fn builds_dns_body_like_resolv_conf() {
        let servers = vec!["10.0.0.10".to_owned(), "10.0.0.11".to_owned()];
        assert_eq!(
            build_resolvconf_body(&servers, Some("corp.example")),
            "nameserver 10.0.0.10\nnameserver 10.0.0.11\nsearch corp.example\n"
        );
    }

    #[test]
    fn prepends_vpn_dns_before_existing_resolv_conf() {
        let servers = vec!["10.0.0.10".to_owned()];
        assert_eq!(
            prepend_vpn_dns_to_resolv_conf(b"nameserver 1.1.1.1\n", &servers, None),
            b"nameserver 10.0.0.10\nnameserver 1.1.1.1\n".to_vec()
        );
    }

    #[test]
    fn does_not_add_dns_lines_that_already_exist() {
        let servers = vec!["10.0.0.10".to_owned(), "10.0.0.11".to_owned()];
        assert_eq!(
            dns_lines_to_add(
                b"nameserver 10.0.0.10\nsearch corp.example\n",
                &servers,
                Some("corp.example")
            ),
            vec!["nameserver 10.0.0.11".to_owned()]
        );
    }

    #[test]
    fn replaces_semicolon_in_dns_search_like_c() {
        let servers = Vec::new();
        assert_eq!(
            build_resolvconf_body(&servers, Some("corp.example;dev.example")),
            "search corp.example dev.example\n"
        );
        assert_eq!(
            build_dns_lines(&servers, Some("corp.example;dev.example")),
            vec!["search corp.example dev.example".to_owned()]
        );
    }

    #[test]
    fn builds_macos_scutil_dns_script() {
        let servers = vec!["10.0.0.10".to_owned(), "10.0.0.11".to_owned()];
        let script = build_macos_scutil_dns_script(
            "State:/Network/Service/openfortivpn-ppp0/DNS",
            "ppp0",
            &servers,
            Some("corp.example;dev.example"),
        );

        assert_eq!(
            script,
            "d.init\nd.add InterfaceName ppp0\nd.add ServerAddresses * 10.0.0.10 10.0.0.11\nd.add SearchDomains * corp.example dev.example\nd.add SupplementalMatchDomains * corp.example dev.example\nset State:/Network/Service/openfortivpn-ppp0/DNS\n"
        );
    }

    #[test]
    fn builds_macos_scutil_cleanup_script_and_key() {
        assert_eq!(
            macos_scutil_dns_key("ppp/0"),
            "State:/Network/Service/openfortivpn-ppp-0/DNS"
        );
        assert_eq!(
            build_macos_scutil_remove_script("State:/Network/Service/openfortivpn-ppp0/DNS"),
            "remove State:/Network/Service/openfortivpn-ppp0/DNS\n"
        );
    }

    #[test]
    fn removes_only_added_dns_lines_on_rollback() {
        let added = vec![
            "nameserver 10.0.0.10".to_owned(),
            "search corp.example".to_owned(),
        ];
        let current = b"nameserver 10.0.0.10\nsearch corp.example\nnameserver 1.1.1.1\nnameserver 10.0.0.10\n";
        assert_eq!(
            remove_added_dns_lines(current, &added),
            b"nameserver 1.1.1.1\nnameserver 10.0.0.10\n".to_vec()
        );
    }
}
