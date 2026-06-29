openfortivpn
============

openfortivpn is a client for PPP+TLS VPN tunnel services rewritten in Rust.
[Here is](https://github.com/adrienverge/openfortivpn) the original project written in C.
It spawns a pppd process and operates the communication between the gateway and
this process.

It is compatible with Fortinet VPNs.

Usage
-----

```shell
openfortivpn --config /path/to/config.conf
```

Examples
--------

* Simply connect to a VPN:
  ```shell
  openfortivpn vpn-gateway:8443 --username=foo
  ```

* Connect to a VPN using an authentication realm:
  ```shell
  openfortivpn vpn-gateway:8443 --username=foo --realm=bar
  ```

* Store password securely with a pinentry program:
  ```shell
  openfortivpn vpn-gateway:8443 --username=foo --pinentry=pinentry-mac
  ```

* Connect with a user certificate and no password:
  ```shell
  openfortivpn vpn-gateway:8443 --username= --password= --user-cert=cert.pem --user-key=key.pem
  ```

* Connect using SAML login:
  ```shell
  openfortivpn vpn-gateway:8443 --saml-login
  ```

* Don't set IP routes and don't add VPN nameservers to `/etc/resolv.conf`:
  ```shell
  openfortivpn vpn-gateway:8443 -u foo --no-routes --no-dns --pppd-no-peerdns
  ```

* Using a configuration file:
  ```shell
  openfortivpn -c /etc/openfortivpn/my-config
  ```

  With `/etc/openfortivpn/my-config` containing:
  ```ini
  host = vpn-gateway
  port = 8443
  username = foo
  set-dns = 0
  pppd-use-peerdns = 0
  # X509 certificate sha256 sum, trust only this one!
  trusted-cert = e46d4aff08ba6914e64daa85bc6112a422fa7ce16631bff0b592a28556f993db
  ```

Configuration
-------------

Configuration is loaded only from the file passed with `--config` / `-c`.
There is no implicit default config file.

The config file format is one `key = value` pair per line. Empty lines and
lines starting with `#` are ignored.

```ini
host = vpn-gateway
port = 8443
username = foo
password = secret
realm = employees
set-routes = true
set-dns = true
trusted-cert = e46d4aff08ba6914e64daa85bc6112a422fa7ce16631bff0b592a28556f993db
```

Command-line options override values loaded from the config file.

Boolean values accept `true`, `false`, `1`, or `0`.

Supported configuration keys:

Authentication and session:

* `host` - VPN gateway hostname or address.
* `port` - VPN gateway port. Default: `443`.
* `username` - VPN username.
* `password` - VPN password.
* `otp` - one-time password / token code.
* `otp-prompt` - prompt text used when requesting OTP.
* `otp-delay` - delay in seconds before sending OTP.
* `no-ftm-push` - disable FortiToken Mobile push flow.
* `pinentry` - pinentry program used to request secrets.
* `realm` - authentication realm.
* `saml-login` - enable SAML login and set local callback port.

Tunnel and network setup:

* `ifname` - preferred VPN interface name.
* `sni` - TLS SNI hostname override.
* `set-routes` - install VPN routes. Default: `true`.
* `half-internet-routes` - use two `/1` routes instead of a default route.
* `set-dns` - install VPN DNS configuration. Default: `true`.
* `use-resolvconf` - use `resolvconf` for DNS setup when available. Default: `true`.
* `persistent` - reconnect interval in seconds. Reconnect attempts are limited to `5`.

PPP / pppd:

* `pppd-use-peerdns` - let `pppd` request peer DNS servers.
* `pppd-log` - pppd log file path.
* `pppd-plugin` - pppd plugin path.
* `pppd-ipparam` - pppd `ipparam` value.
* `pppd-ifname` - pppd interface name.
* `pppd-call` - pppd call profile name.
* `pppd-accept-remote` - accept remote PPP address. Default: `true`.
* `ppp-system` - PPP system profile name.

TLS and certificates:

* `trusted-cert` - trusted peer certificate SHA256 digest. Can be repeated.
* `ca-file` - custom CA bundle path.
* `user-cert` - client certificate path.
* `user-key` - client private key path.
* `pem-passphrase` - passphrase for PEM private key.
* `insecure-ssl` - disable certificate verification.
* `cipher-list` - accepted for compatibility, but unsupported by the Rustls TLS backend.
* `min-tls` - minimum TLS version: `1.0`, `1.1`, `1.2`, or `1.3`. Rustls supports TLS 1.2+.
* `seclevel-1` - accepted for compatibility, but unsupported by the Rustls TLS backend.

Logging and compatibility:

* `use-syslog` - log to syslog on Unix.
* `user-agent` - HTTP User-Agent sent to the VPN gateway. Default: `Mozilla/5.0 SV1`.
* `hostcheck` - hostcheck response value.
* `check-virtual-desktop` - virtual desktop check response value.

Ignored in config files:

* `cookie`
* `cookie-on-stdin`

Smartcard
---------

Smartcard support needs `openssl pkcs engine` and `opensc` to be installed.
The pkcs11-engine from libp11 needs to be compiled with p11-kit-devel installed.
Check [#464](https://github.com/adrienverge/openfortivpn/issues/464) for a discussion
of known issues in this area.

To make use of your smartcard put at least `pkcs11:` to the user-cert config or commandline
option. It takes the full or a partial PKCS#11 token URI.

```ini
user-cert = pkcs11:
user-cert = pkcs11:token=someuser
user-cert = pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=012345678;token=someuser
username =
password =
```

In most cases `user-cert = pkcs11:` will do it, but if needed you can get the token-URI
with `p11tool --list-token-urls`.

Multiple readers are currently not supported.

Smartcard support has been tested with Yubikey under Linux, but other PIV enabled
smartcards may work too. On Mac OS X Mojave it is known that the pkcs engine-by-id
is not found.

## Installing

Check out releases to get a binary

### Building and installing from source

To build and install `openfortivpn` from source, ensure you have Rust and Cargo installed (via [rustup](https://rustup.rs/)).

```shell
# Clone the repository
git clone https://github.com/adrienverge/openfortivpn.git
cd openfortivpn

# Build the project
cargo build --release

# The binary will be located at target/release/openfortivpn
# You can install it to your system (e.g., /usr/local/bin)
sudo cp target/release/openfortivpn /usr/local/bin/
```

Experimental SOCKS5H proxy mode
--------------------------------

Instead of creating a system-wide VPN tunnel, `openfortivpn` can run an isolated
local SOCKS5H proxy:

```shell
openfortivpn vpn-gateway:8443 --username=foo --proxy 127.0.0.1:1180
```

Or with a configuration file:

```shell
openfortivpn --config /path/to/config.conf --proxy 127.0.0.1:1180
```

Use `--socks5-hostname` with clients such as `curl` so hostnames are resolved
through the VPN DNS servers instead of the local system resolver:

```shell
curl --socks5-hostname 127.0.0.1:1180 http://internal.example/
```

Proxy mode uses the same authentication and VPN allocation flow as normal tunnel
mode, but does not spawn `pppd` and does not modify system routes or DNS. It
runs its own userspace PPP/TCP stack and applies VPN routes internally for proxy
connections.

Current limitations:

* experimental feature;
* TCP `CONNECT` only;
* IPv4 only;
* DNS supports A records over TCP through VPN DNS servers;
* no UDP ASSOCIATE, ICMP, IPv6, or system-wide routing;
* only applications configured to use the SOCKS5H proxy will use the VPN.

Running as root?
----------------

openfortivpn needs elevated privileges at three steps during tunnel set up:

* when spawning a `/usr/sbin/pppd` process;
* when setting IP routes through VPN (when the tunnel is up);
* when adding nameservers to `/etc/resolv.conf` (when the tunnel is up).

For these reasons, you need to use `sudo openfortivpn`.
If you need it to be usable by non-sudoer users, you might consider adding an
entry in `/etc/sudoers` or a file under `/etc/sudoers.d`.

For example:
```shell
visudo -f /etc/sudoers.d/openfortivpn
```
```text
Cmnd_Alias  OPENFORTIVPN = /usr/bin/openfortivpn

%adm       ALL = (ALL) OPENFORTIVPN
```
Adapt the above example by changing the `openfortivpn` path or choosing
a group different from `adm` - such as a dedicated `openfortivpn` group.

**Warning**: Make sure only trusted users can run openfortivpn as root!
As described in [#54](https://github.com/adrienverge/openfortivpn/issues/54),
a malicious user could use `--pppd-plugin` and `--pppd-log` options to divert
the program's behaviour.

SSO/SAML/2FA
------------

In some cases, the server may require the VPN client to load and interact
with a web page containing JavaScript. Depending on the complexity of the
web page, interpreting the web page might be beyond the reach of a command
line program such as openfortivpn.

In such cases, you may use an external program spawning a full-fledged
web browser such as
[openfortivpn-webview](https://github.com/gm-vm/openfortivpn-webview)
to authenticate and retrieve a session cookie. This cookie can be fed
to openfortivpn using option `--cookie-on-stdin`. Obviously, such a
solution requires a graphic session.

When started using `--saml-login` the program creates a web server that
accepts SAML login requests. To login using SAML you just have to open
`<your-vpn-domain>/remote/saml/start?redirect=1` and follow the login steps.
At the end of the login process the page will be redirected to
`http://127.0.0.1:8020/?id=<session-id>`

Contributing
------------

Feel free to make pull requests!
