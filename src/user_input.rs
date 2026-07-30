use std::io::Write;

#[cfg(unix)]
use crate::error::OpenfortivpnError;
use crate::error::Result;
use crate::pinentry;

pub fn read_secret(pinentry_program: Option<&str>, hint: &str, prompt: &str) -> Result<String> {
    if let Some(program) = pinentry_program.filter(|program| !program.is_empty()) {
        return pinentry::read_password(program, hint, prompt);
    }

    prompt_secret(prompt)
}

#[cfg(unix)]
fn prompt_secret(prompt: &str) -> Result<String> {
    use nix::sys::termios::{tcgetattr, tcsetattr, LocalFlags, SetArg};
    use std::os::fd::AsFd;

    print!("{prompt}");
    std::io::stdout().flush()?;

    let stdin = std::io::stdin();
    let fd = stdin.as_fd();
    let original = tcgetattr(fd).map_err(|err| {
        OpenfortivpnError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("failed to read terminal settings: {err}"),
        ))
    })?;
    let mut no_echo = original.clone();
    no_echo.local_flags.remove(LocalFlags::ECHO);
    tcsetattr(fd, SetArg::TCSANOW, &no_echo).map_err(|err| {
        OpenfortivpnError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("failed to disable terminal echo: {err}"),
        ))
    })?;

    let mut secret = String::new();
    let read_result = std::io::stdin().read_line(&mut secret);
    let restore_result = tcsetattr(fd, SetArg::TCSANOW, &original);
    println!();

    read_result?;
    if let Err(err) = restore_result {
        return Err(OpenfortivpnError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("failed to restore terminal echo: {err}"),
        )));
    }

    Ok(secret.trim_end_matches(['\r', '\n']).to_owned())
}

#[cfg(not(unix))]
fn prompt_secret(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut secret = String::new();
    std::io::stdin().read_line(&mut secret)?;
    Ok(secret.trim_end_matches(['\r', '\n']).to_owned())
}

pub fn secret_hint(
    username: &str,
    realm: Option<&str>,
    gateway_host: &str,
    purpose: &str,
) -> String {
    format!(
        "{}_{}_{}_{}",
        username,
        realm.unwrap_or_default(),
        gateway_host,
        purpose
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_secret_hint_like_c() {
        assert_eq!(
            secret_hint("user", Some("realm"), "vpn.example", "2fa"),
            "user_realm_vpn.example_2fa"
        );
        assert_eq!(
            secret_hint("user", None, "vpn.example", "password"),
            "user__vpn.example_password"
        );
    }
}
