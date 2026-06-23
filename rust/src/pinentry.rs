use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};

use crate::error::{OpenfortivpnError, Result};

pub fn read_password(program: &str, hint: &str, prompt: &str) -> Result<String> {
    let mut child = Command::new(program)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|err| {
            OpenfortivpnError::Auth(format!(
                "failed to start pinentry program {program:?}: {err}"
            ))
        })?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| OpenfortivpnError::Auth("failed to open pinentry stdin".to_owned()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| OpenfortivpnError::Auth("failed to open pinentry stdout".to_owned()))?;
    let mut stdout = BufReader::new(stdout);

    if let Err(err) = read_pinentry_response(&mut stdout) {
        return Err(finish_child_with_error(&mut child, err));
    }
    if let Err(err) = exchange(&mut stdin, &mut stdout, "SETTITLE VPN Password\n") {
        return Err(finish_child_with_error(&mut child, err));
    }
    if let Err(err) = exchange(&mut stdin, &mut stdout, "SETDESC VPN Requires a Password\n") {
        return Err(finish_child_with_error(&mut child, err));
    }
    if let Err(err) = exchange(
        &mut stdin,
        &mut stdout,
        &format!("SETKEYINFO {}\n", uri_escape(hint)),
    ) {
        return Err(finish_child_with_error(&mut child, err));
    }
    if let Err(err) = exchange(
        &mut stdin,
        &mut stdout,
        &format!("SETPROMPT {}\n", uri_escape(prompt)),
    ) {
        return Err(finish_child_with_error(&mut child, err));
    }
    let password = match exchange(&mut stdin, &mut stdout, "GETPIN\n") {
        Ok(value) => value.unwrap_or_default(),
        Err(err) => return Err(finish_child_with_error(&mut child, err)),
    };

    drop(stdin);
    wait_for_child(child)?;
    Ok(password)
}

fn finish_child_with_error(child: &mut Child, err: OpenfortivpnError) -> OpenfortivpnError {
    let _ = child.kill();
    let _ = child.wait();
    err
}

fn wait_for_child(mut child: Child) -> Result<()> {
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(OpenfortivpnError::Auth(format!(
            "pinentry exited with status {status}"
        )))
    }
}

fn exchange(
    stdin: &mut ChildStdin,
    stdout: &mut impl BufRead,
    command: &str,
) -> Result<Option<String>> {
    stdin.write_all(command.as_bytes())?;
    stdin.flush()?;
    read_pinentry_response(stdout)
}

fn read_pinentry_response(stdout: &mut impl BufRead) -> Result<Option<String>> {
    let mut line = String::new();
    let read = stdout.read_line(&mut line)?;
    if read == 0 {
        return Err(OpenfortivpnError::Auth(
            "short read from pinentry".to_owned(),
        ));
    }
    let line = line.trim_end_matches(['\r', '\n']);

    if line == "OK" {
        return Ok(None);
    }
    if let Some(value) = line.strip_prefix("OK ") {
        return Ok(Some(uri_unescape(value)?));
    }
    if let Some(value) = line.strip_prefix("D ") {
        return Ok(Some(uri_unescape(value)?));
    }
    if let Some(value) = line.strip_prefix("ERR ") {
        let detail = value
            .split_once(' ')
            .map(|(_, text)| uri_unescape(text))
            .transpose()?
            .unwrap_or_else(|| value.to_owned());
        return Err(OpenfortivpnError::Auth(format!(
            "pinentry returned error: {detail}"
        )));
    }
    if let Some(value) = line.strip_prefix("S ERROR") {
        return Err(OpenfortivpnError::Auth(format!(
            "pinentry returned error: {}",
            value.trim()
        )));
    }

    Err(OpenfortivpnError::Auth(format!(
        "pinentry protocol error: {line}"
    )))
}

fn uri_escape(value: &str) -> String {
    let mut escaped = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            escaped.push(byte as char);
        } else {
            escaped.push_str(&format!("%{byte:02X}"));
        }
    }
    escaped
}

fn uri_unescape(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if bytes[i + 1] == b'%' {
                out.push(b'%');
                i += 2;
                continue;
            }
            if let Some(decoded) = decode_hex_pair(bytes[i + 1], bytes[i + 2]) {
                out.push(decoded);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }

    String::from_utf8(out).map_err(|err| {
        OpenfortivpnError::Auth(format!("pinentry returned invalid UTF-8 data: {err}"))
    })
}

fn decode_hex_pair(high: u8, low: u8) -> Option<u8> {
    Some(hex_value(high)? << 4 | hex_value(low)?)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn uri_escape_matches_pinentry_expectations() {
        assert_eq!(
            uri_escape("user realm@example password"),
            "user%20realm%40example%20password"
        );
        assert_eq!(uri_escape("abc-_.~XYZ09"), "abc-_.~XYZ09");
    }

    #[test]
    fn uri_unescape_accepts_hex_and_double_percent() {
        assert_eq!(uri_unescape("abc%20def").unwrap(), "abc def");
        assert_eq!(uri_unescape("abc%%def").unwrap(), "abc%def");
    }

    #[test]
    fn reads_ok_and_data_responses() {
        assert_eq!(
            read_pinentry_response(&mut Cursor::new(b"OK\n")).unwrap(),
            None
        );
        assert_eq!(
            read_pinentry_response(&mut Cursor::new(b"D secret%20value\n")).unwrap(),
            Some("secret value".to_owned())
        );
    }

    #[test]
    fn rejects_pinentry_errors() {
        assert!(read_pinentry_response(&mut Cursor::new(b"ERR 83886179 canceled\n")).is_err());
        assert!(read_pinentry_response(&mut Cursor::new(b"WHAT\n")).is_err());
    }
}
