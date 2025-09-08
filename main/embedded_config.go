package main

// EmbeddedConfig 内置的Xray配置
// 这是一个基本的VLESS配置示例，你可以根据需要修改
const EmbeddedConfig = `{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "tag": "socks",
      "port": 10808,
      "listen": "127.0.0.1",
      "protocol": "socks",
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ],
        "routeOnly": false
      },
      "settings": {
        "auth": "noauth",
        "udp": true,
        "allowTransparent": false
      }
    },
    {
      "tag": "http",
      "port": 10809,
      "listen": "127.0.0.1",
      "protocol": "http",
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ],
        "routeOnly": false
      },
      "settings": {
        "auth": "noauth",
        "udp": true,
        "allowTransparent": false
      }
    }
  ],
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "gitlab.520531.xyz",
            "port": 443,
            "users": [
              {
                "id": "502ab807-8a9f-46ae-9cf8-3dc51fb4c807",
                "email": "t@t.tt",
                "security": "auto",
                "encryption": "none"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "grpc",
        "security": "reality",
        "realitySettings": {
          "serverName": "gitlab.520531.xyz",
          "fingerprint": "chrome",
          "show": false,
          "publicKey": "AF76D3V0ubxd-2Xg5lTuGHv1T1NSle6h-gx36VaqYFw",
          "shortId": "a82b83f1928d172c",
          "spiderX": ""
        },
        "grpcSettings": {
          "serviceName": "Xe5dT0qRt7w",
          "multiMode": false,
          "idle_timeout": 60,
          "health_check_timeout": 20,
          "permit_without_stream": false,
          "initial_windows_size": 0
        }
      },
      "mux": {
        "enabled": false,
        "concurrency": -1
      }
    },
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {}
    },
    {
      "tag": "block",
      "protocol": "blackhole",
      "settings": {
        "response": {
          "type": "http"
        }
      }
    }
  ],
  "dns": {
    "hosts": {
      "dns.google": "8.8.8.8",
      "proxy.example.com": "127.0.0.1"
    },
    "servers": [
      {
        "address": "223.5.5.5",
        "domains": [
          "geosite:cn"
        ],
        "expectIPs": [
          "geoip:cn"
        ]
      },
      "1.1.1.1",
      "8.8.8.8",
      "https://dns.google/dns-query",
      {
        "address": "223.5.5.5",
        "domains": [
          "gitlab.520531.xyz"
        ]
      }
    ]
  },
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api"
      },
      {
        "type": "field",
        "outboundTag": "proxy",
        "ip": [
          "172.18.0.0/16"
        ]
      },
      {
        "type": "field",
        "port": "0-65535",
        "outboundTag": "direct",
        "domain": [
          "git.ainuoya.cn",
          "localhost",
          "sh.ixiatiao.com"
        ]
      },
      {
        "type": "field",
        "port": "0-65535",
        "outboundTag": "direct",
        "ip": [
          "172.16.0.0/16",
          "166.108.234.24",
          "127.0.0.1"
        ]
      },
      {
        "type": "field",
        "outboundTag": "proxy",
        "domain": [
          "domain:googleapis.cn",
          "domain:gstatic.com"
        ]
      },
      {
        "type": "field",
        "port": "443",
        "network": "udp",
        "outboundTag": "proxy"
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "ip": [
          "geoip:private"
        ]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "domain": [
          "geosite:private"
        ]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "ip": [
          "223.5.5.5",
          "223.6.6.6",
          "2400:3200::1",
          "2400:3200:baba::1",
          "119.29.29.29",
          "1.12.12.12",
          "120.53.53.53",
          "2402:4e00::",
          "2402:4e00:1::",
          "180.76.76.76",
          "2400:da00::6666",
          "114.114.114.114",
          "114.114.115.115",
          "114.114.114.119",
          "114.114.115.119",
          "114.114.114.110",
          "114.114.115.110",
          "180.184.1.1",
          "180.184.2.2",
          "101.226.4.6",
          "218.30.118.6",
          "123.125.81.6",
          "140.207.198.6",
          "1.2.4.8",
          "210.2.4.8",
          "52.80.66.66",
          "117.50.22.22",
          "2400:7fc0:849e:200::4",
          "2404:c2c0:85d8:901::4",
          "117.50.10.10",
          "52.80.52.52",
          "2400:7fc0:849e:200::8",
          "2404:c2c0:85d8:901::8",
          "117.50.60.30",
          "52.80.60.30"
        ]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "domain": [
          "domain:alidns.com",
          "domain:doh.pub",
          "domain:dot.pub",
          "domain:360.cn",
          "domain:onedns.net"
        ]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "ip": [
          "geoip:cn"
        ]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "domain": [
          "geosite:cn"
        ]
      },
      {
        "type": "field",
        "outboundTag": "proxy",
        "domain": [
          "geosite:category-ads-all"
        ]
      },
      {
        "type": "field",
        "port": "0-65535",
        "outboundTag": "proxy"
      }
    ]
  }
}`

// UseEmbeddedConfig 是否使用内置配置的标志
var UseEmbeddedConfig = true
