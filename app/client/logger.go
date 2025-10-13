package client

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/log"
)

// LogLevel represents the logging level
type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
	LogLevelNone // Disable all logs
)

var (
	// currentLogLevel is the global log level for the client package
	currentLogLevel = LogLevelError // Default to ERROR, matching Java implementation
	// logEnabled controls whether logging is enabled
	logEnabled = true
)

// InitLogger initializes the logger configuration from environment variables
// Reference: OkHttpClientExternal.java Logger.baseLevel = Logger.Level.INFO
func InitLogger() {
	// Check if logging is enabled via environment variable
	if enabled := os.Getenv("PROXY_CLIENT_LOG_ENABLED"); enabled != "" {
		if strings.ToLower(enabled) == "false" || enabled == "0" {
			logEnabled = false
			currentLogLevel = LogLevelNone
			return
		}
	}

	// Set log level from environment variable
	// PROXY_CLIENT_LOG_LEVEL can be: DEBUG, INFO, WARN, ERROR, NONE
	levelStr := os.Getenv("PROXY_CLIENT_LOG_LEVEL")
	if levelStr == "" {
		levelStr = "ERROR" // Default to ERROR matching Java implementation
	}

	switch strings.ToUpper(levelStr) {
	case "DEBUG":
		currentLogLevel = LogLevelDebug
	case "INFO":
		currentLogLevel = LogLevelInfo
	case "WARN", "WARNING":
		currentLogLevel = LogLevelWarn
	case "ERROR":
		currentLogLevel = LogLevelError
	case "NONE":
		currentLogLevel = LogLevelNone
		logEnabled = false
	default:
		currentLogLevel = LogLevelNone
		logEnabled = false
	}
}

// clientLog logs a message if the level is enabled
func clientLog(level LogLevel, format string, args ...interface{}) {
	if !logEnabled || level < currentLogLevel {
		return
	}

	// Get caller information (similar to Java implementation)
	_, file, line, ok := runtime.Caller(2)
	callerInfo := ""
	if ok {
		// Extract just the filename
		for i := len(file) - 1; i > 0; i-- {
			if file[i] == '/' || file[i] == '\\' {
				file = file[i+1:]
				break
			}
		}
		callerInfo = fmt.Sprintf("(%s:%d)", file, line)
	}

	// Format message
	msg := fmt.Sprintf(format, args...)
	timestamp := time.Now().Format("2006-01-02 15:04:05.000")

	var levelStr string
	var severity log.Severity

	switch level {
	case LogLevelDebug:
		levelStr = "DEBUG"
		severity = log.Severity_Debug
	case LogLevelInfo:
		levelStr = "INFO"
		severity = log.Severity_Info
	case LogLevelWarn:
		levelStr = "WARN"
		severity = log.Severity_Warning
	case LogLevelError:
		levelStr = "ERROR"
		severity = log.Severity_Error
	default:
		return
	}

	// Format: [timestamp] LEVEL caller: message
	formattedMsg := fmt.Sprintf("[%s] [ProxyClient] %s %s: %s", timestamp, levelStr, callerInfo, msg)

	// Log to xray's logging system
	log.Record(&log.GeneralMessage{
		Severity: severity,
		Content:  formattedMsg,
	})
}

// Debug logs a debug message
func logDebug(format string, args ...interface{}) {
	clientLog(LogLevelDebug, format, args...)
}

// Info logs an info message
func logInfo(format string, args ...interface{}) {
	clientLog(LogLevelInfo, format, args...)
}

// Warn logs a warning message
func logWarn(format string, args ...interface{}) {
	clientLog(LogLevelWarn, format, args...)
}

// Error logs an error message
func logError(format string, args ...interface{}) {
	clientLog(LogLevelError, format, args...)
}

// IsDebugEnabled returns true if debug logging is enabled
func isDebugEnabled() bool {
	return logEnabled && currentLogLevel <= LogLevelDebug
}

// IsInfoEnabled returns true if info logging is enabled
func isInfoEnabled() bool {
	return logEnabled && currentLogLevel <= LogLevelInfo
}
