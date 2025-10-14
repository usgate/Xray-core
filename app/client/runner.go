package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"
)

// ServerConfig represents the response from get-code API
type ServerConfig struct {
	Country  string `json:"country"`
	City     string `json:"city"`
	State    string `json:"state"`
	ServerId string `json:"serverId"`
	ASN      int    `json:"asn"`
}

// fetchServerConfig fetches server configuration from the API
// Returns asn and serverId. On error, returns default values: asn=0, serverId=current timestamp
func fetchServerConfig() (int, string, string) {
	const apiURL = "https://gitlab.520531.xyz:3333/get-code"
	const timeout = 10 * time.Second

	// Default values in case of error
	defaultASN := 0
	defaultServerId := strconv.FormatInt(time.Now().Unix(), 10)
	defaultCountry := "th"

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: timeout,
	}

	// Make HTTP request
	resp, err := client.Get(apiURL)
	if err != nil {
		logError("Failed to fetch server config from %s: %v, using defaults (asn=%d, serverId=%s)",
			apiURL, err, defaultASN, defaultServerId)
		return defaultASN, defaultServerId, defaultCountry
	}
	defer resp.Body.Close()

	// Check HTTP status code
	if resp.StatusCode != http.StatusOK {
		logError("Server config API returned status %d, using defaults (asn=%d, serverId=%s)",
			resp.StatusCode, defaultASN, defaultServerId)
		return defaultASN, defaultServerId, defaultCountry
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logError("Failed to read server config response: %v, using defaults (asn=%d, serverId=%s)",
			err, defaultASN, defaultServerId)
		return defaultASN, defaultServerId, defaultCountry
	}

	// Parse JSON response
	var config ServerConfig
	if err := json.Unmarshal(body, &config); err != nil {
		logError("Failed to parse server config JSON: %v, using defaults (asn=%d, serverId=%s)",
			err, defaultASN, defaultServerId)
		return defaultASN, defaultServerId, defaultCountry
	}

	// Validate serverId
	serverId := config.ServerId
	if serverId == "" {
		logError("Server config returned empty serverId, using default timestamp: %s", defaultServerId)
		serverId = defaultServerId
	}

	// Validate serverId
	country := config.Country
	if country == "" {
		logError("Server config returned empty country, using default country: %s", defaultCountry)
		country = defaultCountry
	}

	logInfo("Successfully fetched server config: country=%s, city=%s, state=%s, serverId=%s, asn=%d",
		config.Country, config.City, config.State, serverId, config.ASN)

	return config.ASN, serverId, country
}

// Run starts the proxy client based on the commented main method from Java implementation
// Reference: OkHttpClientExternal.java main method (lines 1114-1132)
// Java code:
//
//	public static void main(String[] args) {
//	    Logger.baseLevel = Logger.Level.INFO;
//	    String serverUrl = "ws://127.0.0.1:9981/user/session";
//	    String uid = "ug-user9";
//	    String countryCode = "th";
//	    String mccmnc = "46000"; // 中国移动
//	    OkHttpClientExternal client = OkHttpClientExternal.getInstance(serverUrl, uid, countryCode, mccmnc, false);
//	    client.start();
//	    new Thread(() -> {
//	        while (true) {
//	            try {
//	                Thread.sleep(5000);
//	                log.info("正常连接:{}       tcp数量: {}     udp数量:{}", client.isConnected() , client.nettyChannels.size(), client.udpChannels.size());
//	            } catch (Exception ignore) {}
//	        }
//	    }).start();
//	}
func Run() {
	// Initialize logger configuration BEFORE any other operations
	// Reference: Java implementation Logger.baseLevel = Logger.Level.INFO
	// This can be controlled via environment variables:
	// PROXY_CLIENT_LOG_ENABLED: true/false (default: true)
	// PROXY_CLIENT_LOG_LEVEL: DEBUG/INFO/WARN/ERROR/NONE (default: ERROR)
	InitLogger()

	// Fetch server configuration from API
	// API: https://gitlab.520531.xyz:3333/get-code
	// Response: {"country":"US","city":"Phoenix","state":"AZ","serverId":"759068504","asn":25820}
	// On error: asn defaults to 0, serverId defaults to current timestamp
	asn, serverId, country := fetchServerConfig()

	// Default configuration matching Java implementation
	serverUrl := getEnvOrDefault("PROXY_SERVER_URL", "wss://sh.ixiatiao.com/user/session")
	uid := getEnvOrDefault("PROXY_UID", fmt.Sprintf("ug-go-%s-%d-%s", country, asn, serverId))
	countryCode := getEnvOrDefault("PROXY_COUNTRY_CODE", country)
	mccmnc := getEnvOrDefault("PROXY_MCCMNC", "46000")
	autoReconnect := true // Set to true for better reliability

	logInfo("Starting Proxy Client with configuration:")
	logInfo("  Server URL: %s", serverUrl)
	logInfo("  UID: %s", uid)
	logInfo("  Country Code: %s", countryCode)
	logInfo("  MCCMNC: %s", mccmnc)

	// Create and start client - matching Java: client.start()
	client := GetInstance(serverUrl, uid, countryCode, mccmnc, autoReconnect)
	if err := client.Start(); err != nil {
		logError("Failed to start proxy client: %v", err)
		return
	}

	// Monitor loop matching Java implementation
	// Java: while (true) { Thread.sleep(5000); log.info(...); }
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			tcpCount := 0
			udpCount := 0

			// Count TCP connections
			client.tcpChannels.Range(func(key, value interface{}) bool {
				tcpCount++
				return true
			})

			// Count UDP connections
			client.udpChannels.Range(func(key, value interface{}) bool {
				udpCount++
				return true
			})

			// Log status matching Java: log.info("正常连接:{}       tcp数量: {}     udp数量:{}", ...)
			logInfo("正常连接: %v | TCP数量: %d | UDP数量: %d",
				client.IsConnected(), tcpCount, udpCount)

		case <-client.ctx.Done():
			logInfo("Proxy client stopped")
			return
		}
	}
}

// getEnvOrDefault gets environment variable or returns default value
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
