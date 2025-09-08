package main

// EmbeddedConfig 内置的Xray配置
// 这是一个基本的VLESS配置示例，你可以根据需要修改
const EmbeddedConfig = `{
    "log": {
        "loglevel": "warning"
    },
    "inbounds": [
        {
			"tag": "in2",
            "listen": "0.0.0.0",
            "port": 10086,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "121326cb-8c6d-4d41-9d88-712a899f09c5"
                    }
                ]
            },
            "streamSettings": {
                "network": "tcp"
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "tag": "block"
        }
    ],
    "routing": {
        "domainStrategy": "AsIs",
        "rules": [
            {
                "type": "field",
                "ip": [
                    "geoip:private"
                ],
                "outboundTag": "block"
            }
        ],
        "rules": [
            {
                "inboundTag": "in2",
                "type": "field",
                "outboundTag": "freedom"
            }
        ]
    }
}
`

// UseEmbeddedConfig 是否使用内置配置的标志
var UseEmbeddedConfig = false
