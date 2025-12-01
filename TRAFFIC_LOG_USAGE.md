# 域名分流流量日志功能使用说明

## 功能介绍

该功能可以在日志中输出每个域名 TCP 连接的分流信息和流量统计，包括：
- 域名
- 是否走分流（与默认出站不同即为分流）
- 使用的出站标签
- 上行流量（字节）
- 下行流量（字节）

## 配置方法

### 默认行为
默认情况下，该功能是**开启**的，无需额外配置。

### 在配置文件中控制

如果需要关闭该功能，可以在 `config.json` 中添加 dispatcher 配置：

```json
{
  "log": {
    "loglevel": "info"
  },
  "inbounds": [...],
  "outbounds": [...],
  "routing": {...},
  "dispatcher": {
    "disableTrafficLog": true
  }
}
```

### 配置项说明

- `dispatcher.disableTrafficLog`: 布尔值，控制是否禁用域名流量日志
  - `true`: 禁用
  - `false` 或不配置: 启用（默认）

## 日志输出格式

当连接关闭时，会输出类似以下格式的日志：

```
[Info] [Traffic] Domain: www.google.com, Routed: yes, Outbound: proxy, Uplink: 12345 bytes, Downlink: 67890 bytes
[Info] [Traffic] Domain: www.baidu.com, Routed: no, Outbound: direct, Uplink: 5432 bytes, Downlink: 9876 bytes
```

### 字段说明

- **Domain**: 连接的目标域名
- **Routed**: 是否通过路由规则匹配（分流）
  - `yes`: 通过路由规则匹配（命中了 routing 规则）
  - `no`: 未通过路由规则（使用默认路由或强制指定出站）
- **Outbound**: 使用的出站标签
- **Uplink**: 上行流量（客户端→服务器），单位：字节
- **Downlink**: 下行流量（服务器→客户端），单位：字节

## 注意事项

1. **仅统计 TCP 流量**：UDP 连接不会被统计
2. **仅统计域名连接**：直接通过 IP 地址的连接不会被统计
3. **连接关闭时输出**：日志在连接正常关闭或异常中断时输出
4. **性能影响**：每个连接增加约 24 字节内存开销（3 个计数器），性能影响可忽略不计

## 应用场景

- 分析哪些域名走了代理分流
- 统计各个域名的流量消耗
- 调试路由规则是否生效
- 监控特定域名的访问情况

## 示例配置

完整的配置示例（启用流量日志）：

```json
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "info"
  },
  "inbounds": [
    {
      "port": 1080,
      "protocol": "socks",
      "settings": {}
    }
  ],
  "outbounds": [
    {
      "tag": "proxy",
      "protocol": "vmess",
      "settings": {...}
    },
    {
      "tag": "direct",
      "protocol": "freedom"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "domain": ["geosite:google"],
        "outboundTag": "proxy"
      }
    ]
  }
}
```

在这个例子中，访问 Google 相关域名时：
- 日志会显示 `Routed: yes, Outbound: proxy`（命中了路由规则）
- 访问其他域名会显示 `Routed: no, Outbound: direct`（使用默认路由）

**注意**：如果没有配置路由规则，或者连接未命中任何规则而使用默认出站，则 `Routed` 会显示 `no`，即使默认出站是代理服务器。

