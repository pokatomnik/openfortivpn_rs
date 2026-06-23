use std::fs::File;

use crate::config::Config;
use crate::error::{OpenfortivpnError, Result};

pub const DEFAULT_PPPD_PATH: &str = "/usr/sbin/pppd";
pub const DEFAULT_PPP_PATH: &str = "/usr/sbin/ppp";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PppdCommand {
    pub program: String,
    pub args: Vec<String>,
}

impl PppdCommand {
    pub fn argv(&self) -> Vec<String> {
        let mut argv = Vec::with_capacity(1 + self.args.len());
        argv.push(self.program.clone());
        argv.extend(self.args.clone());
        argv
    }
}

pub struct PppdChild {
    pub master: File,
    #[cfg(unix)]
    pub pid: nix::unistd::Pid,
}

#[cfg(unix)]
pub fn spawn_pppd(command: &PppdCommand) -> Result<PppdChild> {
    unix::spawn_pppd(command)
}

#[cfg(unix)]
pub fn terminate_pppd(pid: nix::unistd::Pid) -> Result<()> {
    unix::terminate_pppd(pid)
}

#[cfg(not(unix))]
pub fn spawn_pppd(_command: &PppdCommand) -> Result<PppdChild> {
    Err(OpenfortivpnError::Pppd(
        "pppd pty spawning is only implemented on Unix platforms".to_owned(),
    ))
}

pub fn build_ppp_command(config: &Config, ppp_path: impl Into<String>) -> PppdCommand {
    let mut args = vec!["-direct".to_owned()];
    if let Some(system) = config
        .ppp_system
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        args.push(system.to_owned());
    }

    PppdCommand {
        program: ppp_path.into(),
        args,
    }
}

pub fn build_pppd_command(config: &Config, pppd_path: impl Into<String>) -> PppdCommand {
    let program = pppd_path.into();
    let mut args = Vec::new();

    if let Some(call) = &config.pppd_call {
        args.push("call".to_owned());
        args.push(call.clone());
    } else {
        args.extend(
            [
                "230400",
                ":169.254.2.1",
                "noipdefault",
                "ipcp-accept-local",
                "noaccomp",
                "noauth",
                "default-asyncmap",
                "nopcomp",
                "receive-all",
                "nodefaultroute",
                "nodetach",
                "lcp-max-configure",
                "40",
                "mru",
                "1354",
            ]
            .into_iter()
            .map(str::to_owned),
        );
    }

    if config.pppd_accept_remote {
        args.push("ipcp-accept-remote".to_owned());
    }

    if config.pppd_use_peerdns {
        args.push("usepeerdns".to_owned());
    }

    if let Some(log) = &config.pppd_log {
        args.push("debug".to_owned());
        args.push("logfile".to_owned());
        args.push(log.clone());
    } else {
        // pppd defaults to logging to fd=1, which would clobber PPP data.
        args.push("logfd".to_owned());
        args.push("2".to_owned());
    }

    if let Some(plugin) = &config.pppd_plugin {
        args.push("plugin".to_owned());
        args.push(plugin.clone());
    }

    if let Some(ipparam) = &config.pppd_ipparam {
        args.push("ipparam".to_owned());
        args.push(ipparam.clone());
    }

    if let Some(ifname) = &config.pppd_ifname {
        args.push("ifname".to_owned());
        args.push(ifname.clone());
    }

    PppdCommand { program, args }
}

#[cfg(unix)]
mod unix {
    use std::ffi::CString;
    use std::fs::File;
    use std::thread;
    use std::time::{Duration, Instant};

    use nix::pty::{forkpty, ForkptyResult};
    use nix::sys::signal::{kill, Signal};
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
    use nix::unistd::execvp;

    use super::*;

    pub fn spawn_pppd(command: &PppdCommand) -> Result<PppdChild> {
        let fork = unsafe { forkpty(None, None) }
            .map_err(|err| OpenfortivpnError::Pppd(format!("forkpty failed: {err}")))?;

        match fork {
            ForkptyResult::Parent { child, master } => Ok(PppdChild {
                master: File::from(master),
                pid: child,
            }),
            ForkptyResult::Child => {
                let argv = command.argv();
                let c_argv = argv
                    .iter()
                    .map(|arg| CString::new(arg.as_str()))
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .unwrap_or_else(|_| std::process::exit(127));
                let program = c_argv.first().cloned().unwrap_or_else(|| {
                    CString::new(DEFAULT_PPPD_PATH).expect("default pppd path has no NUL")
                });
                let args = c_argv.iter().map(|arg| arg.as_c_str()).collect::<Vec<_>>();
                let _ = execvp(&program, &args);
                std::process::exit(127);
            }
        }
    }

    pub fn terminate_pppd(pid: nix::unistd::Pid) -> Result<()> {
        if is_reaped(pid)? {
            return Ok(());
        }

        let _ = kill(pid, Signal::SIGTERM);
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if is_reaped(pid)? {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
        }

        let _ = kill(pid, Signal::SIGKILL);
        loop {
            match waitpid(pid, None) {
                Ok(WaitStatus::Exited(_, _)) | Ok(WaitStatus::Signaled(_, _, _)) => return Ok(()),
                Ok(_) => continue,
                Err(nix::errno::Errno::ECHILD) => return Ok(()),
                Err(err) => {
                    return Err(OpenfortivpnError::Pppd(format!(
                        "waitpid after SIGKILL failed: {err}"
                    )))
                }
            }
        }
    }

    fn is_reaped(pid: nix::unistd::Pid) -> Result<bool> {
        match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::StillAlive) => Ok(false),
            Ok(_) => Ok(true),
            Err(nix::errno::Errno::ECHILD) => Ok(true),
            Err(err) => Err(OpenfortivpnError::Pppd(format!("waitpid failed: {err}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_ppp_system_args() {
        let cfg = Config {
            ppp_system: Some("fortivpn".to_owned()),
            ..Config::default()
        };
        let argv = build_ppp_command(&cfg, DEFAULT_PPP_PATH).argv();

        assert_eq!(argv, vec![DEFAULT_PPP_PATH, "-direct", "fortivpn"]);
    }

    #[test]
    fn builds_ppp_direct_without_system_name() {
        let cfg = Config {
            ppp_system: Some(String::new()),
            ..Config::default()
        };
        let argv = build_ppp_command(&cfg, DEFAULT_PPP_PATH).argv();

        assert_eq!(argv, vec![DEFAULT_PPP_PATH, "-direct"]);
    }

    #[test]
    fn builds_default_pppd_args() {
        let cfg = Config::default();
        let cmd = build_pppd_command(&cfg, DEFAULT_PPPD_PATH);
        let argv = cmd.argv();

        assert_eq!(argv[0], DEFAULT_PPPD_PATH);
        assert!(argv.contains(&"230400".to_owned()));
        assert!(argv.contains(&":169.254.2.1".to_owned()));
        assert!(argv.contains(&"ipcp-accept-local".to_owned()));
        assert!(argv.contains(&"ipcp-accept-remote".to_owned()));
        assert!(argv.windows(2).any(|w| w == ["logfd", "2"]));
    }

    #[test]
    fn builds_call_mode_with_extra_options() {
        let mut cfg = Config::default();
        cfg.pppd_call = Some("vpn".to_owned());
        cfg.pppd_use_peerdns = true;
        cfg.pppd_log = Some("/tmp/pppd.log".to_owned());
        cfg.pppd_ifname = Some("ppp-openforti".to_owned());

        let argv = build_pppd_command(&cfg, DEFAULT_PPPD_PATH).argv();
        assert_eq!(&argv[0..3], [DEFAULT_PPPD_PATH, "call", "vpn"]);
        assert!(argv.contains(&"usepeerdns".to_owned()));
        assert!(argv
            .windows(3)
            .any(|w| w == ["debug", "logfile", "/tmp/pppd.log"]));
        assert!(argv.windows(2).any(|w| w == ["ifname", "ppp-openforti"]));
    }
}
