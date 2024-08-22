# DPI-bypassing transparent proxy

Usage:

```shell
sudo adpi --listen-address 127.0.0.1:1280 --split-positions 1 --split-positions 3 --split-host --fwmark 1280
```

Nftables:

```nftables
table ip nat {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
        tcp dport { 80, 443 } meta mark != 1280 redirect to :1280
    }

    chain output {
        type nat hook output priority dstnat; policy accept;
        tcp dport { 80, 443 } meta mark != 1280 redirect to :1280
    }
}
```
