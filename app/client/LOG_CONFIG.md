# Proxy Client 日志配置说明

## 概述

Proxy Client 实现了独立的日志系统，参考 OkHttpClientExternal.java 的日志实现。日志可以通过环境变量进行配置，支持灵活的开关和级别控制。

## 配置方式

### 环境变量

在启动 Xray 之前，可以通过以下环境变量配置日志：

#### 1. `PROXY_CLIENT_LOG_ENABLED`

控制日志是否启用。

- **可选值**: `true` 或 `false` (或 `0`)
- **默认值**: `true` (启用)
- **示例**:
  ```bash
  # Windows CMD
  set PROXY_CLIENT_LOG_ENABLED=false
  
  # Windows PowerShell
  $env:PROXY_CLIENT_LOG_ENABLED="false"
  
  # Linux/Mac
  export PROXY_CLIENT_LOG_ENABLED=false
  ```

#### 2. `PROXY_CLIENT_LOG_LEVEL`

设置日志级别。

- **可选值**: `DEBUG`, `INFO`, `WARN`, `ERROR`, `NONE`
- **默认值**: `ERROR` (仅显示错误，匹配 Java 实现)
- **级别说明**:
  - `DEBUG`: 显示所有日志，包括调试信息（最详细）
  - `INFO`: 显示信息、警告和错误日志
  - `WARN`: 显示警告和错误日志
  - `ERROR`: 仅显示错误日志（默认）
  - `NONE`: 禁用所有日志

- **示例**:
  ```bash
  # Windows CMD
  set PROXY_CLIENT_LOG_LEVEL=INFO
  
  # Windows PowerShell
  $env:PROXY_CLIENT_LOG_LEVEL="INFO"
  
  # Linux/Mac
  export PROXY_CLIENT_LOG_LEVEL=INFO
  ```

## 日志级别对比

| 级别 | 输出内容 | 适用场景 |
|------|---------|---------|
| DEBUG | 所有日志（包括连接详情、会话ID、数据传输等） | 开发调试 |
| INFO | 连接状态、配置信息、统计信息 | 正常运行监控 |
| WARN | 警告信息（如数据块过大） | 生产环境 |
| ERROR | 仅错误信息 | 生产环境（默认） |
| NONE | 无日志输出 | 性能优先场景 |

## 完整配置示例

### Windows CMD

```cmd
REM 配置 Proxy Client
set PROXY_SERVER_URL=wss://sh.ixiatiao.com/user/session
set PROXY_UID=ug-go-user9
set PROXY_COUNTRY_CODE=th
set PROXY_MCCMNC=46000

REM 配置日志级别为 INFO
set PROXY_CLIENT_LOG_LEVEL=INFO

REM 启动 Xray
xray.exe run -c config.json
```

### Windows PowerShell

```powershell
# 配置 Proxy Client
$env:PROXY_SERVER_URL="wss://sh.ixiatiao.com/user/session"
$env:PROXY_UID="ug-go-user9"
$env:PROXY_COUNTRY_CODE="th"
$env:PROXY_MCCMNC="46000"

# 配置日志级别为 INFO
$env:PROXY_CLIENT_LOG_LEVEL="INFO"

# 启动 Xray
.\xray.exe run -c config.json
```

### Linux/Mac

```bash
# 配置 Proxy Client
export PROXY_SERVER_URL=wss://sh.ixiatiao.com/user/session
export PROXY_UID=ug-go-user9
export PROXY_COUNTRY_CODE=th
export PROXY_MCCMNC=46000

# 配置日志级别为 INFO
export PROXY_CLIENT_LOG_LEVEL=INFO

# 启动 Xray
./xray run -c config.json
```

## 日志输出格式

日志格式如下：
```
[2025-01-13 10:30:45.123] [ProxyClient] INFO (client.go:120): Starting ProxyClient with UID: ug-go-user9
[2025-01-13 10:30:45.456] [ProxyClient] INFO (client.go:223): Connected to server successfully
[2025-01-13 10:30:50.789] [ProxyClient] INFO (runner.go:85): 正常连接: true | TCP数量: 3 | UDP数量: 1
```

格式说明：
- `[时间戳]`: 精确到毫秒
- `[ProxyClient]`: 标识为 Proxy Client 的日志
- `级别`: DEBUG/INFO/WARN/ERROR
- `(文件:行号)`: 日志来源位置
- `消息内容`: 具体日志信息

## 故障排查

### 1. 连接问题排查

建议使用 `DEBUG` 级别查看详细连接信息：

```bash
set PROXY_CLIENT_LOG_LEVEL=DEBUG
```

DEBUG 级别会显示：
- WebSocket 连接详情
- 会话创建和关闭
- 数据传输细节
- TCP/UDP 连接状态

### 2. 生产环境配置

生产环境建议使用 `ERROR` 级别（默认），仅记录错误：

```bash
set PROXY_CLIENT_LOG_LEVEL=ERROR
```

### 3. 完全禁用日志

如果需要最佳性能，可以完全禁用日志：

```bash
set PROXY_CLIENT_LOG_ENABLED=false
```

或者：

```bash
set PROXY_CLIENT_LOG_LEVEL=NONE
```

## 与 Java 实现的对应关系

| Java | Go | 说明 |
|------|-----|------|
| `Logger.baseLevel = Logger.Level.DEBUG` | `PROXY_CLIENT_LOG_LEVEL=DEBUG` | 调试级别 |
| `Logger.baseLevel = Logger.Level.INFO` | `PROXY_CLIENT_LOG_LEVEL=INFO` | 信息级别 |
| `Logger.baseLevel = Logger.Level.WARN` | `PROXY_CLIENT_LOG_LEVEL=WARN` | 警告级别 |
| `Logger.baseLevel = Logger.Level.ERROR` | `PROXY_CLIENT_LOG_LEVEL=ERROR` | 错误级别（默认） |

## 注意事项

1. **初始化顺序**: 日志配置在 `runner.go` 的 `Run()` 方法最开始执行，确保所有后续操作的日志都受配置控制。

2. **环境变量优先级**: 环境变量配置优先于默认值，方便在不同环境中调整日志级别。

3. **性能考虑**: 
   - `DEBUG` 级别会产生大量日志，仅在开发/调试时使用
   - 生产环境推荐使用 `ERROR` 或 `WARN` 级别
   - 对性能要求极高的场景可使用 `NONE` 完全禁用

4. **日志集成**: Proxy Client 的日志通过 Xray 的日志系统输出，会遵循 Xray 的日志配置（如日志文件、格式等）。

## 示例场景

### 场景 1: 开发调试

```bash
set PROXY_CLIENT_LOG_LEVEL=DEBUG
```

输出所有日志，包括每个连接、数据传输的详细信息。

### 场景 2: 正常监控

```bash
set PROXY_CLIENT_LOG_LEVEL=INFO
```

每 5 秒输出一次连接统计信息：
```
[2025-01-13 10:30:50.789] [ProxyClient] INFO: 正常连接: true | TCP数量: 3 | UDP数量: 1
```

### 场景 3: 生产环境

```bash
set PROXY_CLIENT_LOG_LEVEL=ERROR
```

仅在出现错误时输出日志，减少日志量。

### 场景 4: 性能优先

```bash
set PROXY_CLIENT_LOG_ENABLED=false
```

完全禁用日志，获得最佳性能。

