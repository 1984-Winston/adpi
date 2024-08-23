# DPI-bypassing transparent proxy

## Setup

### Start transparent proxy

```shell
cargo build --release
sudo target/release/adpi --split-positions 1
```

You can set as many split positions as you want by repeating `--split-positions`
arg, but usually one split is enough - try 1, 3, maybe 7. `--split-host` is also
supported.

### Setup firewall

Nftables:

```nftables
table inet adpi-nat {
  chain pre {
    type nat hook prerouting priority dstnat; policy accept;
    tcp dport { 80, 443 } meta mark != 1280 redirect to :1280
  }

  chain out {
    type nat hook output priority mangle - 10; policy accept;
    tcp dport { 80, 443 } meta mark != 1280 redirect to :1280
  }
}
```

Iptables:

```shell
# forwarded traffic
iptables -t nat -A PREROUTING -p tcp -m multiport --dports 80,443 -m mark ! --mark 1280 -j REDIRECT --to-port 1280
ip6tables -t nat -A PREROUTING -p tcp -m multiport --dports 80,443 -m mark ! --mark 1280 -j REDIRECT --to-port 1280
# output traffic
iptables -t nat -A OUTPUT -p tcp -m multiport --dports 80,443 -m mark ! --mark 1280 -j REDIRECT --to-port 1280
ip6tables -t nat -A OUTPUT -p tcp -m multiport --dports 80,443 -m mark ! --mark 1280 -j REDIRECT --to-port 1280
```

## On NixOS

Add input in flake.nix:

```nix
adpi.url = "github:1984-Winston/adpi";
```

Import nixos module:

```nix
imports = [ inputs.adpi.nixosModules.default ];
```

Enable service:

```nix
services.adpi = {
  enable = true;
  setupFirewall = true;
  extraArgs = "--split-positions 1";
};
```

## Usage

```text
Usage: adpi [OPTIONS]

Options:
  -t, --threads <THREADS>
          Number of worker threads [default: 4]
  -l, --listen-address <LISTEN_ADDRESS>
          Socket addresses to bind listeners [default: 127.0.0.1:1280 [::1]:1280]
  -c, --split-positions <SPLIT_POSITIONS>
          Split positions in TLS ClientHello message
  -s, --split-host
          Split TLS ClientHello at host
  -m, --fwmark <FWMARK>
          Set fwmark for outgoing sockets. Disabled if 0 [default: 1280]
  -h, --help
          Print help
  -V, --version
          Print version
```
