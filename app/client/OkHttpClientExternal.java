package okhttp3;

import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.*;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import io.netty.channel.socket.nio.NioDatagramChannel;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;


public class OkHttpClientExternal {

    private static final Logger log = Logger.getLogger(OkHttpClientExternal.class);

    private final String uid;

    private final String mccmnc;

    private final String countryCode;

    private final boolean autoReconnect;

    private WebSocketClient webSocketClient;
    private final String serverUrl;
    // 事件循环，默认会创建核心数 * 2个线程，且不会自动回收
    private EventLoopGroup eventLoopGroup;
    private final Map<String, Channel> nettyChannels = new ConcurrentHashMap<>();
    // 存储UDP会话
    private final Map<String, Channel> udpChannels = new ConcurrentHashMap<>();
    // 添加一个原子布尔值来控制重连状态
    private final AtomicBoolean reconnecting = new AtomicBoolean(false);
    // 添加一个字段存储连接建立任务
    private ScheduledExecutorService heartbeatScheduler;

    // 防御性清理僵尸连接
    private ScheduledExecutorService cleanupScheduler;

    // 添加UDP通道活跃时间记录
    private final Map<String, Long> udpLastActiveTime = new ConcurrentHashMap<>();
    // TCP通道活跃时间记录
    private final Map<String, Long> tcpLastActiveTime = new ConcurrentHashMap<>();
    // 预留协议
    private final static byte[] unusedBytes = new byte[4];

    private final Object lock = new Object();

    // 分块大小
    final int MAX_CHUNK_SIZE = 8 * 1024;


    private boolean running = true;

    private static OkHttpClientExternal instance;


    private static class UUIDUtil {

        /**
         * 16字节转换为uuid字符串，示例uuid 361ba8fa8f81462fb6dfb25c13ccdbef
         */
        public static String convertToUUIDString(byte[] bytes) {        if (bytes.length != 16) {
            throw new IllegalArgumentException("Byte array must be 16 bytes long");
        }
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 16; i++) {
                sb.append(String.format("%02x", bytes[i]));
            }
            return sb.toString();
        }


        public static String genUUID() {
            return UUID.randomUUID().toString().replace("-", "");
        }

        /**
         * uuid字符串转换为16字节
         */
        public static byte[] convertToBytes(String cleanUuid) {
            if (cleanUuid.length() != 32) {
                throw new IllegalArgumentException();
            }

            byte[] bytes = new byte[16];
            for (int i = 0; i < 16; i++) {
                int index = i * 2;
                bytes[i] = (byte) ((Character.digit(cleanUuid.charAt(index), 16) << 4)
                        + Character.digit(cleanUuid.charAt(index + 1), 16));
            }
            return bytes;
        }
    }

    private static class Logger {

        public static Logger.Level baseLevel = Logger.Level.ERROR;

        public enum Level {
            DEBUG(1), INFO(2), WARN(3), ERROR(4);

            private final int level;

            Level(int level) {
                this.level = level;
            }

            public int getLevel() {
                return level;
            }
        }


        public static Logger getLogger(Class<?> clazz) {
            return new Logger();
        }

        public void debug(String msg) {
            println(Logger.Level.DEBUG, msg);
        }

        public void debug(String msg, Object... args) {
            println(Logger.Level.DEBUG, msg, args);
        }

        public void info(String msg) {
            println(Logger.Level.INFO, msg);
        }

        public void info(String msg, Object... args) {
            println(Logger.Level.INFO, msg, args);
        }

        public void warn(String msg) {
            println(Logger.Level.WARN, msg);
        }

        public void warn(String msg, Throwable t) {
            println(Logger.Level.WARN, msg, t);
        }

        public void warn(String msg, Object... args) {
            println(Logger.Level.WARN, msg, args);
        }

        public void error(String msg) {
            println(Logger.Level.WARN, msg);
        }

        public void error(String msg, Throwable t) {
            println(Logger.Level.ERROR, msg, t);
        }

        public void error(String msg, Object... args) {
            println(Logger.Level.ERROR, msg, args);
        }

        private void println(Logger.Level level, String msg, Object... args) {
            try {
                if (level.getLevel() < baseLevel.getLevel()) {
                    return;
                }
                // msg 支持 {} 替换符 , 最后一个可以是exception，如果是exception，则需要打印出来exception信息以及堆栈
                if (args != null) {
                    for (Object arg : args) {
                        msg = msg.replaceFirst("\\{}", arg.toString());
                    }
                }
                // 获取调用者的类名和方法名
                // 这里可以使用 Thread.currentThread().getStackTrace() 获取调用者信息
                Thread currentThread = Thread.currentThread();
                StackTraceElement[] stackTrace = currentThread.getStackTrace();
                StackTraceElement caller = stackTrace[3]; // 通常第3个元素是调用者
                String className = caller.getClassName();
                String methodName = caller.getMethodName();
                int lineNumber = caller.getLineNumber();
                // 打印日志信息
                msg = String.format("[%tF %<tT.%<tL] %s.%s(%s:%d): %s",System.currentTimeMillis(), className, methodName, caller.getFileName(), lineNumber, msg);
                // 如果最后一个参数是Throwable，则打印异常信息
                if (args != null && args.length > 0 && args[args.length - 1] instanceof Throwable) {
                    Throwable t = (Throwable) args[args.length - 1];
                    System.err.println((level.name() + ": " + msg + " Exception: " + t.getMessage()));
                    t.printStackTrace(System.out);
                } else  {
                    System.out.println(level.name() + ": " + msg);
                }
            } catch (Exception e) {
                System.err.println("generic logger error: " + e.getMessage());
            }
        }


    }

    private static class EncryptUtil {

        public static byte[] XOR_KEY;

        public static void encrypt(ByteBuffer input) {
            // 保存原始 position 以便恢复
            int originalPosition = input.position();

            // 直接在输入缓冲区上执行 XOR 操作
            int keyLength = XOR_KEY.length;
            int keyIndex = 0;
            while (input.hasRemaining()) {
                byte b = input.get(); // 读取当前字节
                input.position(input.position() - 1); // 回退 position 以覆盖
                input.put((byte) (b ^ XOR_KEY[keyIndex])); // 写入加密后的字节
                keyIndex = (keyIndex + 1) % keyLength; // 循环使用密钥
            }

            // 恢复原始 position
            input.position(originalPosition);
        }

        public static void decrypt(ByteBuffer originData) {
            // xor 解密和加密是相同的
            encrypt(originData);
        }


        public static void encrypt(byte[] originData) {
            xorEncrypt(originData, XOR_KEY);
        }


        public static void decrypt(byte[] originData) {
            encrypt(originData);
        }

        /**
         * 使用异或进行字节数组加密
         * @param data 原始数据
         * @param key 密钥字节数组
         * @return 加密后的数据
         */
        public static void xorEncrypt(byte[] data, byte[] key) {
            for (int i = 0; i < data.length; i++) {
                data[i] = (byte) (data[i] ^ key[i % key.length]);
            }
        }

        /**
         * 使用异或进行字节数组解密（与加密算法相同）
         * @param encryptedData 加密数据
         * @param key 密钥字节数组
         * @return 解密后的原始数据
         */
        public static void xorDecrypt(byte[] encryptedData, byte[] key) {
            // 异或加密的特性是：加密和解密使用相同算法
            xorEncrypt(encryptedData, key);
        }

        /**
         * 生成随机密钥
         * @param length 密钥长度
         * @return 生成的随机密钥
         */
        public static byte[] generateRandomKey(int length) {
            byte[] key = new byte[length];
            new SecureRandom().nextBytes(key);
            return key;
        }

        /**
         * 将密钥转换为Base64字符串方便存储
         * @param key 密钥字节数组
         * @return Base64编码的密钥字符串
         */
        public static String keyToString(byte[] key) {
            return Base64.getEncoder().encodeToString(key);
        }

        /**
         * 从Base64字符串恢复密钥
         * @param keyStr Base64编码的密钥字符串
         * @return 密钥字节数组
         */
        public static byte[] stringToKey(String keyStr) {
            return Base64.getDecoder().decode(keyStr);
        }

    }


    /**
     * 获取MobileClientSimulator实例
     * 如果实例已存在且配置未变更，则返回现有实例
     * 如果配置变更，则重新创建实例
     * 如果ws连接已打开，则不重新连接
     * @param serverUrl 服务器URL
     * @param uid 用户ID
     * @param countryCode 国家代码
     * @param mccmnc 移动国家代码和网络代码
     * @return MobileClientSimulator实例
     */
    public static OkHttpClientExternal getInstance(String serverUrl, String uid, String countryCode, String mccmnc) {
        return getInstance(serverUrl, uid, countryCode, mccmnc, false);
    }

    /**
     *
     * @param serverUrl 服务器URL ws://ip:port/usgate
     * @param uid 用户ID
     * @param countryCode 国家代码
     * @param mccmnc 移动国家代码和网络代码
     * @param autoReconnect 是否自动重连ws
     * @return
     */
    public static OkHttpClientExternal getInstance(String serverUrl, String uid, String countryCode, String mccmnc, boolean autoReconnect) {
        if (instance == null) {
            synchronized (OkHttpClientExternal.class) {
                if (instance == null) {
                    instance = new OkHttpClientExternal(serverUrl, uid, countryCode, mccmnc, autoReconnect);
                }
            }
        } else {
            // 检查配置是否变更，如果变更则重新创建实例
            synchronized (OkHttpClientExternal.class) {
                if (!serverUrl.equals(instance.serverUrl) || !uid.equals(instance.uid)) {
                    log.info("检测到配置变更，重新创建MobileClientSimulator实例");
                    if (instance != null) {
                        instance.stop(); // 停止旧实例
                    }
                    instance = new OkHttpClientExternal(serverUrl, uid, countryCode, mccmnc, autoReconnect);
                }
            }
        }
        return instance;
    }

    private OkHttpClientExternal(String serverUrl, String uid, String countryCode, String mccmnc, boolean autoReconnect) {
        this.serverUrl = serverUrl;
        this.uid = uid != null ? uid : UUIDUtil.genUUID();
        // 设置XOR加密密钥为用户id
        EncryptUtil.XOR_KEY = uid.getBytes(StandardCharsets.UTF_8);
        this.countryCode = countryCode != null && !countryCode.isEmpty() ? countryCode : "unknow";
        this.mccmnc = mccmnc != null && !mccmnc.isEmpty() && !"000".equals(mccmnc)? mccmnc : "000000";
        this.autoReconnect = autoReconnect;
    }
    public void start() {
        synchronized (lock) {
            log.info("正在启动MobileClientSimulator...");
            running = true;
            reconnecting.set(false);
            // 确保所有线程池都是新创建的，避免使用已关闭的线程池
            if (heartbeatScheduler == null || heartbeatScheduler.isShutdown()) {
                heartbeatScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                    Thread t = new Thread(r, "h-" + uid);
                    t.setDaemon(true);
                    return t;
                });
            }

            if (cleanupScheduler == null || cleanupScheduler.isShutdown()) {
                cleanupScheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                    Thread t = new Thread(r, "c-" + uid);
                    t.setDaemon(true);
                    return t;
                });
            }

            if (eventLoopGroup == null || eventLoopGroup.isShutdown()) {
                eventLoopGroup = new NioEventLoopGroup();
            }

            startChannelCleanup();
            startHeartbeat();
            connectToServer();
            log.info("启动手机客户端模拟器，UUID: {}", uid);
        }
    }



    public void restart() {
        synchronized (lock) {
            stop();
            start();
            log.info("启动手机客户端模拟器，UUID: {}", uid);
        }
    }

    private void startChannelCleanup() {
        cleanupScheduler.scheduleWithFixedDelay(() -> {
            long currentTime = System.currentTimeMillis();
            long inactiveThreshold = 60 * 1000; // 1分钟不活动则清理
            int closedTcpCount = 0;
            int closedUdpCount = 0;
            // 清理不活跃的UDP通道
            for (Iterator<Map.Entry<String, Long>> it = udpLastActiveTime.entrySet().iterator(); it.hasNext();) {
                Map.Entry<String, Long> entry = it.next();
                String sessionId = entry.getKey();
                Long lastActive = entry.getValue();

                if (currentTime - lastActive > inactiveThreshold && udpChannels.containsKey(sessionId)) {
                    log.info("UDP通道{}已{}分钟不活动，准备关闭", sessionId, inactiveThreshold / 60000);
                    closeUDPConnection(-1, sessionId);
                    it.remove();
                    closedUdpCount++;
                }
            }
            if (closedUdpCount > 0) {
                log.info("已清理{}个不活跃的UDP通道", closedUdpCount);
            }

            // 清理不活跃的TCP通道
            for (Iterator<Map.Entry<String, Long>> it = tcpLastActiveTime.entrySet().iterator(); it.hasNext();) {
                Map.Entry<String, Long> entry = it.next();
                String sessionId = entry.getKey();
                Long lastActive = entry.getValue();

                if (currentTime - lastActive > inactiveThreshold && nettyChannels.containsKey(sessionId)) {
                    log.info("TCP通道{}已{}分钟不活动，准备关闭", sessionId, inactiveThreshold / 60000);
                    // 客户端自己清理，服务器也会自己清理
                    closeTCPConnection(sessionId, false);
                    it.remove();
                    closedTcpCount++;
                }
            }
            if (closedTcpCount > 0) {
                log.info("已清理{}个不活跃的TCP通道", closedTcpCount);
            }

        }, 30, 30, TimeUnit.SECONDS);
    }

    private void connectToServer() {
        try {
            if (webSocketClient != null && webSocketClient.isOpen()) {
                // 如果连接已经打开，则不需要重新连接
                log.info("WebSocket连接已打开，无需重新连接");
            }

            CountDownLatch latch = new CountDownLatch(1);

            // tc 代表国家
            // tm 代表运营商编号
            webSocketClient = new WebSocketClient(new URI(serverUrl + "?clientId=" + uid + "&tc=" + countryCode + "&tm=" + mccmnc)) {
                @Override
                public void onOpen(ServerHandshake handshake) {
                    log.info("连接到远程服务器成功");
                    latch.countDown(); // 释放等待
                }

                @Override
                public void onMessage(String message) {
                    log.info("收到控制消息: {}", message);
                    // 处理控制消息，如心跳检测等
                }

                @Override
                public void onMessage(ByteBuffer bytes) {
                    processProxyRequest(bytes);
                }

                @Override
                public void onClose(int code, String reason, boolean remote) {
                    log.info("连接关闭: {}, {} , {}", code, reason, remote);
                    if (running) {
                        if (autoReconnect) {
                            scheduleReconnect();
                            return;
                        }
                        log.debug("连接关闭，自动重连已禁用");
                    }
                }

                @Override
                public void onError(Exception ex) {
                    log.error("连接错误: {}", ex.getMessage());
                    latch.countDown(); // 释放等待
                    if (running) {
                        if (autoReconnect) {
                            scheduleReconnect();
                            return;
                        }
                        log.debug("连接错误，自动重连已禁用");
                    }
                }
            };
            log.info("开始连接到服务器: {}", serverUrl);
            webSocketClient.connect();
            // 等待连接完成，最多等待5秒
            latch.await(5, TimeUnit.SECONDS);
            log.info("连接状态: {}", isConnected());
        } catch (URISyntaxException e) {
            log.error("URL格式错误", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); // 恢复中断状态
            log.error("连接被中断", e);
        }
    }

    private void processProxyRequest(ByteBuffer data) {
        try {
            // 解析代理请求
            // 格式：[16字节会话ID][1字节命令类型][其他数据]
            byte[] sessionIdBytes = new byte[16];
            data.get(sessionIdBytes);
            String sessionId = UUIDUtil.convertToUUIDString(sessionIdBytes);
            byte commandType = data.get();
            Channel tcpChannel = nettyChannels.get(sessionId);
            Channel udpChannel = udpChannels.get(sessionId);
            // 如果没有tcp和udp通道，并且命令类型不是创建连接(0)和udp(7)，命令推送(9)，则直接返回
            if (tcpChannel == null && udpChannel == null && commandType != 0 && commandType != 7 && commandType != 9) {
                return;
            }
            log.debug("处理代理请求: sessionId={}, commandType={}", sessionId, commandType);
            switch (commandType) {
                case 0: // 新建连接
                    byte[] hostBytes = new byte[data.getInt()];
                    data.get(hostBytes);
                    EncryptUtil.decrypt(hostBytes);
                    String host = new String(hostBytes, StandardCharsets.UTF_8);
                    int port = data.getInt();
                    log.debug("创建新连接({}:{}): {}", host, port, sessionId);
                    createNewConnection(sessionId, host, port);
                    break;

                case 1: // 数据转发
                    if (tcpChannel == null) {
                        log.debug("未成功建立: 结束！ sessionId={}", sessionId);
                        break;
                    }
                    updateTcpActiveTime(sessionId);
                    log.debug("数据转发: sessionId={}, 数据长度={}, channel active:{}", sessionId, data.remaining(), tcpChannel.isActive());
                    if (tcpChannel.isActive()) {
                        byte[] proxyData = new byte[data.remaining()];
                        data.get(proxyData);
                        // 加密
                        EncryptUtil.decrypt(proxyData);
                        // proxyData 转 16进制
                        StringBuilder hexString = new StringBuilder();
                        for (byte b : proxyData) {
                            hexString.append(String.format("%02x", b));
                            hexString.append(" ");
                        }
                        log.debug("数据转发: sessionId={}, 数据：{}", sessionId, hexString);
                        ByteBuf buf = Unpooled.wrappedBuffer(proxyData);
                        tcpChannel.writeAndFlush(buf);
                    }
                    break;

                case 2: // 关闭连接
                    log.debug("收到关闭指令: sessionId={}", sessionId);
                    closeTCPConnection(sessionId, false);
                    break;

                case 6: // 读取短信
                    log.info("读取短信: sessionId={}", sessionId);
                    String sms = ""; // 这里可以替换为实际读取的短信内容
                    byte[] smsBytes = sms.getBytes(StandardCharsets.UTF_8);
                    ByteBuffer smsData = ByteBuffer.allocate(4 + 17 + smsBytes.length);
                    smsData.put(unusedBytes);
                    smsData.put(UUIDUtil.convertToBytes(sessionId));
                    smsData.put((byte) 6); // 7表示读取短信
                    smsData.put(smsBytes);
                    smsData.flip();
                    wsSend(smsData);
                    break;
                case 7: // UDP数据
                    log.debug("处理UDP数据: sessionId={}", sessionId);
                    // 更新活跃时间
                    updateUdpActiveTime(sessionId);
                    // 这里可以添加处理UDP数据的逻辑
                    processUDPData(sessionId, data);
                    break;
                case 8: // 关闭UDP
                    log.debug("关闭UDP通道: sessionId={}", sessionId);
                    closeUDPConnection(8, sessionId);
                    break;
                case 9: // 服务器推送指令 暂未实现
                    log.debug("处理服务器推送指令: sessionId={}", sessionId);
                    // 这里可以添加处理服务器推送指令的逻辑
                    break;
            }
        } catch (Exception e) {
            log.error("处理代理请求出错", e);
        }
    }

    /**
     * 在每次UDP数据发送或接收时更新活跃时间
     */
    private void updateUdpActiveTime(String sessionId) {
        udpLastActiveTime.put(sessionId, System.currentTimeMillis());
    }

    /**
     * 在每次TCP数据发送或接收时更新活跃时间
     */
    private void updateTcpActiveTime(String sessionId) {
        tcpLastActiveTime.put(sessionId, System.currentTimeMillis());
    }

    private void processUDPData(String sessionId, ByteBuffer data) {
        // ByteBuffer buffer = ByteBuffer.allocate(16 + 1 + 4 + hostBytes.length + 4 + 4 + udpData.length);
        //
        //        buffer.put(sessionIdBytes);             // 会话ID
        //        buffer.put((byte) 7);                   // 命令类型：7=UDP 数据
        //        buffer.putInt(hostBytes.length);        // 目标主机长度
        //        buffer.put(hostBytes);                  // 目标主机
        //        buffer.putInt(targetPort);              // 目标端口
        //
        //        buffer.putInt(udpData.length);          // 数据长度
        //        EncryptUtil.encrypt(udpData);           // 加密数据
        //        buffer.put(udpData);                    // 数据内容
        // 读取目标主机
        int hostLength = data.getInt();
        byte[] hostBytes = new byte[hostLength];
        data.get(hostBytes);
        String targetHost = new String(hostBytes, StandardCharsets.UTF_8);

        // 读取目标端口
        int targetPort = data.getInt();

        // 读取数据内容
        int dataLength = data.getInt();
        byte[] udpData = new byte[dataLength];
        data.get(udpData);

        // 解密数据
        EncryptUtil.decrypt(udpData);

        log.debug("UDP数据: sessionId:{}  目标={}:{}, 数据长度={}",
                sessionId, targetHost, targetPort, dataLength);

        // 创建UDP客户端并发送数据
        sendUdpData(sessionId, targetHost, targetPort, udpData);
    }




    /**
     * 发送UDP数据并处理响应
     */
    private void sendUdpData(String sessionId, String targetHost, int targetPort, byte[] data) {
        try {
            // 检查是否已有该会话的UDP通道
            Channel channel = udpChannels.get(sessionId);

            if (channel == null || !channel.isActive()) {
                // 创建新的UDP通道 - 使用Netty的NioDatagramChannel
                Bootstrap bootstrap = new Bootstrap();
                bootstrap.group(eventLoopGroup)
                        .channel(NioDatagramChannel.class)
                        .handler(new ChannelInitializer<NioDatagramChannel>() {
                            @Override
                            protected void initChannel(NioDatagramChannel ch) {
                                ch.pipeline().addLast(new SimpleChannelInboundHandler<io.netty.channel.socket.DatagramPacket>() {
                                    @Override
                                    protected void channelRead0(ChannelHandlerContext ctx, io.netty.channel.socket.DatagramPacket packet) {
                                        try {
                                            log.debug("收到UDP服务器( {}:{} )响应, sessionId: {}", targetHost, targetPort, sessionId);
                                            ByteBuf content = packet.content();
                                            int bytesReceived = content.readableBytes();
                                            byte[] responseData = new byte[bytesReceived];
                                            content.readBytes(responseData);
                                            // responseData > 8192 时
                                            if (responseData.length > MAX_CHUNK_SIZE) {
                                                log.warn("UDP响应数据超过最大块大小: {} > {}", responseData.length, MAX_CHUNK_SIZE);
                                            }
                                            log.debug("原始服务器响应: sessionId: {}  内容: {}", sessionId, responseData);
                                            // 加密响应数据
                                            EncryptUtil.encrypt(responseData);

                                            // 构造发送给服务器的响应
                                            // 格式：会话ID(16) + 命令类型(1) + 数据长度(4) + 数据(变长)
                                            ByteBuffer response = ByteBuffer.allocate(4 + 16 + 1 + 4 + responseData.length);
                                            response.put(unusedBytes);
                                            response.put(UUIDUtil.convertToBytes(sessionId));
                                            response.put((byte) 7); // UDP数据类型
                                            response.putInt(responseData.length);
                                            response.put(responseData);
                                            response.flip();

                                            // 发送给服务器
                                            wsSend(response);

                                            log.debug("UDP响应 ( {}:{} ) 返回: sessionId={}, 数据长度={}", targetHost, targetPort, sessionId, bytesReceived);
                                        } catch (Exception e) {
                                            log.warn("处理UDP响应时出错", e);
                                            closeUDPConnection(-1, sessionId);
                                        }
                                    }

                                    @Override
                                    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
                                        closeUDPConnection(-1, sessionId);
                                    }

                                    @Override
                                    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
                                        closeUDPConnection(-1, sessionId);
                                    }
                                });
                            }
                        });

                // 绑定通道
                ChannelFuture bindFuture = bootstrap.bind(0).sync();
                channel = bindFuture.channel();

                // 存储通道引用
                udpChannels.put(sessionId, channel);
                log.debug("UDP通道已创建: sessionId={}, localPort={}",
                        sessionId, ((InetSocketAddress)channel.localAddress()).getPort());
            }

            // 发送UDP数据
            ByteBuf buf = Unpooled.wrappedBuffer(data);
            io.netty.channel.socket.DatagramPacket packet =
                    new io.netty.channel.socket.DatagramPacket(buf, new InetSocketAddress(targetHost, targetPort));
            channel.writeAndFlush(packet);

            log.debug("UDP数据已发送: sessionId={}, 目标={}:{}, 数据长度={}",
                    sessionId, targetHost, targetPort, data.length);

        } catch (Exception e) {
            log.error("发送UDP数据时出错: {}", e.getMessage(), e);
            closeUDPConnection(-1, sessionId);
        }
    }


    private void createNewConnection(String sessionId, String host, int port) {
        Bootstrap bootstrap = new Bootstrap();
        bootstrap.group(eventLoopGroup)
                .channel(NioSocketChannel.class)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 5000)
                .option(ChannelOption.SO_KEEPALIVE, true)
                .handler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        ch.pipeline().addLast(new SimpleChannelInboundHandler<ByteBuf>() {
                            @Override
                            protected void channelRead0(ChannelHandlerContext ctx, ByteBuf msg) {
                                int bytesRead = msg.readableBytes();
                                byte[] buffer = new byte[bytesRead];
                                msg.readBytes(buffer);

                                // 打印响应的数据大小
                                log.debug("收到目标服务器({}:{})响应: size: {} byte", host, port, bytesRead);

                                // 加密
                                EncryptUtil.encrypt(buffer);

                                // 如果数据小于最大块大小，直接发送
                                if (bytesRead <= MAX_CHUNK_SIZE) {
                                    ByteBuffer response = ByteBuffer.allocate(4 + 16 + 1 + 1 + bytesRead);
                                    response.put(unusedBytes);
                                    response.put(UUIDUtil.convertToBytes(sessionId));
                                    response.put((byte) 1); // 1表示数据转发
                                    response.put((byte) 0); // 是否分片
                                    response.put(buffer);
                                    response.flip();
                                    wsSend(response);
                                } else {
                                    // 数据大于最大块大小，分块发送
                                    log.debug("({}:{})数据大小超过{}字节，分块发送，总大小: {}", host, port, MAX_CHUNK_SIZE, bytesRead);
                                    int offset = 0;
                                    // 计算分块序号
                                    byte chunkIndex = 0;
                                    // 计算分块数量 - 默认最大分块数量为128
                                    int chunkCount = (int) Math.ceil(bytesRead * 1.0d / MAX_CHUNK_SIZE);
                                    if (chunkCount > 128) {
                                        log.debug("({}:{})数据大小超过{}字节，分块数量超过128，无法处理", host, port, MAX_CHUNK_SIZE);
                                        return;
                                    }
                                    // 分片uuid
                                    byte[] conversation = UUIDUtil.convertToBytes(UUIDUtil.genUUID());
                                    while (offset < bytesRead) {
                                        // 计算当前块的大小
                                        int chunkSize = Math.min(MAX_CHUNK_SIZE, bytesRead - offset);
                                        ByteBuffer chunk = ByteBuffer.allocate(4 + 16 + 1 + 1 + 16 + 1 + 1 + chunkSize);
                                        chunk.put(unusedBytes);
                                        chunk.put(UUIDUtil.convertToBytes(sessionId));  // 16字节会话ID
                                        chunk.put((byte) 1);                            // 1字节命令类型
                                        chunk.put((byte) 1);                            // 1字节分片标志
                                        chunk.put(conversation);                        // 16字节分片会话ID
                                        chunk.put((byte) chunkCount);                   // 分片数量
                                        chunk.put(chunkIndex);                          // 分片序号
                                        chunk.put(buffer, offset, chunkSize);
                                        chunk.flip();
                                        wsSend(chunk);
                                        offset += chunkSize;
                                        chunkIndex++;
                                    }

                                }
                            }



                            @Override
                            public void channelInactive(ChannelHandlerContext ctx) {
                                // 发送一个传输结束的通知，但保持连接
                                ByteBuffer endOfDataMsg = ByteBuffer.allocate(4 + 17);
                                endOfDataMsg.put(unusedBytes);
                                endOfDataMsg.put(UUIDUtil.convertToBytes(sessionId));
                                endOfDataMsg.put((byte) 4); // 4表示数据传输结束
                                endOfDataMsg.flip();
                                wsSend(endOfDataMsg);
                                // 关闭连接
                                log.debug("通道已关闭: sessionId:{} {}:{}", sessionId,  host, port);
                                // 此时服务器不知道连接已关闭，所以需要通知服务器
                                closeTCPConnection(sessionId, true);
                            }

                            @Override
                            public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
                                log.warn("Netty连接异常: {}", cause.getMessage());
                                closeTCPConnection(sessionId, true);
                            }
                        });
                    }
                });
        log.debug("创建连接: {}:{}", host, port);
        // 连接到目标服务器
        bootstrap.connect(host, port).addListener((ChannelFutureListener) future -> {
            if (future.isSuccess()) {
                Channel channel = future.channel();
                nettyChannels.put(sessionId, channel);
                updateTcpActiveTime(sessionId);
                // 先发送一个连接成功的通知
                ByteBuffer connectedMsg = ByteBuffer.allocate(4 + 16 + 1);
                connectedMsg.put(unusedBytes);
                connectedMsg.put(UUIDUtil.convertToBytes(sessionId));
                connectedMsg.put((byte) 3); // 3表示连接已建立成功
                connectedMsg.flip();

                log.debug("连接成功: {}:{} session-id:{}", host, port, sessionId);
                wsSend(connectedMsg);
            } else {
                log.debug("连接目标服务器({}:{})失败: {}", host, port, sessionId);
                // 通知连接失败
                closeTCPConnection(sessionId, true);
            }
        });
    }

    private void closeTCPConnection(String sessionId, boolean notifyServer) {
        log.debug("关闭tcp连接: sessionId={}", sessionId);
        // 关闭Netty通道
        Channel channel = nettyChannels.remove(sessionId);
        if (channel != null) {
            channel.close();
            log.debug("关闭TCP连接: {}", sessionId);
        }

        if (!notifyServer) {
            // 2表示连接由服务器主动关闭，不需要通知
            log.debug("TCP连接已关闭: sessionId={}", sessionId);
            return;
        }

        // 通知服务端连接已关闭
        ByteBuffer closeMsg = ByteBuffer.allocate(4 + 17);
        closeMsg.put(unusedBytes);
        closeMsg.put(UUIDUtil.convertToBytes(sessionId));
        closeMsg.put((byte) 2); // 2表示连接关闭
        closeMsg.flip();

        log.debug("发送关闭连接消息: sessionId={}", sessionId);
        wsSend(closeMsg);
        log.debug("成功关闭连接消息: sessionId={}", sessionId);
    }

    private void closeUDPConnection(int cause, String sessionId) {
        log.debug("关闭udp连接: sessionId={}", sessionId);

        // 关闭UDP通道
        Channel udpChannel = udpChannels.remove(sessionId);
        if (udpChannel != null) {
            udpChannel.close();
            log.debug("关闭UDP通道: {}", sessionId);
        }

        if (cause == 8) {
            // 8表示连接由服务器主动关闭，不需要通知
            log.debug("UDP连接已关闭: sessionId={}", sessionId);
            return;
        }

        // 通知服务端连接已关闭
        ByteBuffer closeMsg = ByteBuffer.allocate(4 + 17);
        closeMsg.put(unusedBytes);
        closeMsg.put(UUIDUtil.convertToBytes(sessionId));
        closeMsg.put((byte) 8); // 2表示连接关闭
        closeMsg.flip();

        log.debug("发送UDP关闭连接消息: sessionId={}", sessionId);
        wsSend(closeMsg);
        log.debug("成功UDP关闭连接消息: sessionId={}", sessionId);
    }

    private void scheduleReconnect() {
        // 如果已经有重连任务在执行，则不再创建新的重连任务
        if (reconnecting.compareAndSet(false, true)) {
            // 使用一个独立的线程来处理重连，避免使用可能已关闭的线程池
            new Thread(() -> {
                try {
                    log.info("计划在10秒后重新连接...");
                    Thread.sleep(10000);

                    if (!running) {
                        log.info("应用已停止，取消重连");
                        return;
                    }

                    if (wsHeartbeat()) {
                        log.info("心跳检测成功，WebSocket连接仍然可用");
                        return;
                    }

                    log.info("尝试重新连接...");

                    // 必须通过心跳检测失败才能触发重连
                    try {
                        if (webSocketClient != null) {
                            webSocketClient.close();
                            webSocketClient = null;
                        }
                    } catch (Exception e) {
                        log.debug("关闭旧WebSocket连接时出错: {}", e.getMessage());
                    }

                    // 重新建立连接
                    connectToServer();

                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    log.info("重连任务被中断");
                } catch (Exception e) {
                    log.error("重连过程中发生异常", e);
                } finally {
                    // 重置重连状态
                    reconnecting.set(false);
                }
            }, "r-" + uid).start();
        } else {
            log.debug("已有重连任务计划中，跳过此次重连请求");
        }
    }

    public void stop() {
        synchronized (lock) {
            log.info("正在停止MobileClientSimulator...");
            running = false;

            // 关闭所有连接
            try {
                for (String sessionId : nettyChannels.keySet()) {
                    log.debug("关闭Netty连接: sessionId={}", sessionId);
                    closeTCPConnection(sessionId, true);
                }
            } catch (Exception e) {
                log.debug("关闭TCP通道时出错: {}", e.getMessage(), e);
            }

            try {
                // 关闭所有UDP通道
                for (String sessionId : udpChannels.keySet()) {
                    log.debug("关闭UDP通道: sessionId={}", sessionId);
                    closeUDPConnection(-1, sessionId);
                }
            } catch (Exception e) {
                log.debug("关闭UDP通道时出错: {}", e.getMessage(), e);
            }

            // 关闭WebSocket连接
            try {
                if (webSocketClient != null) {
                    webSocketClient.close();
                    webSocketClient = null;
                }
            } catch (Exception e) {
                log.debug("关闭WebSocket连接时出错: {}", e.getMessage(), e);
            }

            // 按顺序关闭线程池，避免RejectedExecutionException
            try {
                if (heartbeatScheduler != null && !heartbeatScheduler.isShutdown()) {
                    heartbeatScheduler.shutdown();
                    if (!heartbeatScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                        log.warn("心跳调度器强制关闭");
                        heartbeatScheduler.shutdownNow();
                    }
                    heartbeatScheduler = null;
                }
            } catch (Exception e) {
                log.debug("关闭心跳调度器时出错: {}", e.getMessage(), e);
            }

            try {
                if (cleanupScheduler != null && !cleanupScheduler.isShutdown()) {
                    cleanupScheduler.shutdown();
                    if (!cleanupScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                        log.warn("清理调度器强制关闭");
                        cleanupScheduler.shutdownNow();
                    }
                    cleanupScheduler = null;
                }
            } catch (Exception e) {
                log.debug("关闭清理调度器时出错: {}", e.getMessage(), e);
            }

            try {
                if (eventLoopGroup != null && !eventLoopGroup.isShutdown()) {
                    eventLoopGroup.shutdownGracefully(2, 5, TimeUnit.SECONDS);
                    eventLoopGroup = null;
                }
            } catch (Exception e) {
                log.debug("关闭事件循环组时出错: {}", e.getMessage(), e);
            }

            log.info("MobileClientSimulator已停止");
        }
    }

    /**
     * 开启心跳检测任务
     */
    private void startHeartbeat() {
        heartbeatScheduler.scheduleWithFixedDelay(() -> {
            if (webSocketClient != null && webSocketClient.isOpen()) {
                boolean success = this.wsHeartbeat();
                if (!success) {
                    log.warn("发送心跳消息失败");
                }
            } else {
                if (autoReconnect) {
                    log.warn("检测到WebSocket连接不可用，尝试重连");
                    scheduleReconnect();
                    return;
                }
                log.debug("心跳检测发现连接不可用，但自动重连已禁用，不会重新连接");
            }
        }, 5, 30, TimeUnit.SECONDS);
    }


    public boolean wsHeartbeat() {
        try {
            // 发送心跳消息，可以是简单的Ping消息
            ByteBuffer pingMsg = ByteBuffer.allocate(4 + 16 + 1);
            byte[] bytes = UUIDUtil.convertToBytes(UUIDUtil.genUUID());
            pingMsg.put(unusedBytes);
            pingMsg.put(bytes);
            pingMsg.put((byte) 5);
            pingMsg.flip();
            log.debug("发送心跳检测消息");
            return wsSend(pingMsg);
        } catch (Exception e) {
            return false;
        }
    }


    private boolean wsSend(ByteBuffer data) {
        if (this.webSocketClient.isOpen()) {
            this.webSocketClient.send(data);
            return true;
        }else {
            // 如果连接不可用，则尝试重连
            if (autoReconnect) {
                log.warn("WebSocket连接不可用，无法发送数据，尝试重连");
                scheduleReconnect();
            }
            return false;
        }
    }

    /**
     * 检查WebSocket连接是否打开
     */
    public boolean isConnected() {
        return webSocketClient != null && webSocketClient.isOpen();
    }


//    public static void main(String[] args) {
//        Logger.baseLevel = Logger.Level.INFO; // 设置日志级别为DEBUG
//        // 默认配置
////        String serverUrl = "wss://sh.ixiatiao.com/user/session";
//        String serverUrl = "ws://127.0.0.1:9981/user/session";
//        String uid = "ug-user9";
//        String countryCode = "th";
//        String mccmnc = "46000"; // 中国移动
//        log.debug("参数: {}", args.length);
//        // 创建并启动客户端模拟器
//        OkHttpClientExternal client = OkHttpClientExternal.getInstance(serverUrl, uid, countryCode, mccmnc, false);
//        client.start();
//        new Thread(() -> {
//            while (true) {
//                try {
//                    // 模拟客户端运行
//                    Thread.sleep(5000);
//                    log.info("正常连接:{}       tcp数量: {}     udp数量:{}", client.isConnected() , client.nettyChannels.size(), client.udpChannels.size());
//                } catch (Exception ignore) {
//                }
//            }
//        }).start();
//    }
}
