package client

import (
	"fmt"
	"os"
	"time"

	"github.com/xtls/xray-core/common/log"
)

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
	// Default configuration matching Java implementation
	serverUrl := getEnvOrDefault("PROXY_SERVER_URL", "wss://sh.ixiatiao.com/user/session")
	uid := getEnvOrDefault("PROXY_UID", "ug-go-user9")
	countryCode := getEnvOrDefault("PROXY_COUNTRY_CODE", "th")
	mccmnc := getEnvOrDefault("PROXY_MCCMNC", "46000")
	autoReconnect := true // Set to true for better reliability

	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  "Starting Proxy Client with configuration:",
	})
	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  fmt.Sprintf("  Server URL: %s", serverUrl),
	})
	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  fmt.Sprintf("  UID: %s", uid),
	})
	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  fmt.Sprintf("  Country Code: %s", countryCode),
	})
	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Info,
		Content:  fmt.Sprintf("  MCCMNC: %s", mccmnc),
	})

	// Create and start client - matching Java: client.start()
	client := GetInstance(serverUrl, uid, countryCode, mccmnc, autoReconnect)
	if err := client.Start(); err != nil {
		log.Record(&log.GeneralMessage{
			Severity: log.Severity_Error,
			Content:  fmt.Sprintf("Failed to start proxy client: %v", err),
		})
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
			log.Record(&log.GeneralMessage{
				Severity: log.Severity_Info,
				Content: fmt.Sprintf("正常连接: %v | TCP数量: %d | UDP数量: %d",
					client.IsConnected(), tcpCount, udpCount),
			})

		case <-client.ctx.Done():
			log.Record(&log.GeneralMessage{
				Severity: log.Severity_Info,
				Content:  "Proxy client stopped",
			})
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
