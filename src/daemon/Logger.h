#pragma once

#include <string>
#include <mutex>
#include <nlohmann/json.hpp>
#include <system_error>

/**
 * Logger is a thread-safe logging system that provides structured logging to syslog with JSON formatting.
 * It supports multiple log levels (DEBUG, INFO, WARNING, ERROR, CRITICAL) and can log both simple messages and structured data.
 * The logger automatically formats timestamps, includes process identification, and handles syslog integration.
 * It's designed to be used across the entire firewall daemon for consistent logging and debugging capabilities.
 */
class Logger {
public:
    /**
     * Enumeration of available log levels for message categorization.
     * Higher levels indicate more severe or important messages.
     */
    enum class LogLevel {
        DEBUG,      ///< Detailed debug information for development
        INFO,       ///< General information about normal operation
        WARNING,    ///< Warning messages for potential issues
        ERROR,      ///< Error messages for recoverable problems
        CRITICAL    ///< Critical errors that may cause system failure
    };

    /**
     * Constructs a new Logger instance with the specified identifier.
     * Opens syslog connection and sets up the logging facility.
     * @param ident Identifier string for the logger (usually process name)
     */
    explicit Logger(const std::string& ident);
    
    /**
     * Destructor that closes the syslog connection and cleans up resources.
     * Ensures proper cleanup of system logging facilities.
     */
    ~Logger();
    
    /**
     * Logs a message with the specified level and optional structured data.
     * Creates a JSON-formatted log entry and sends it to syslog.
     * @param level Log level for the message
     * @param message Human-readable message text
     * @param data Optional JSON data to include with the message
     */
    void log(LogLevel level, const std::string& message, const nlohmann::json& data = {});
    
    /**
     * Logs an error message with system error code information.
     * Automatically extracts error details and includes them in the log entry.
     * @param message Error message description
     * @param ec System error code containing error details
     */
    void logError(const std::string& message, const std::error_code& ec);
    
    /**
     * Logs connection events with structured connection data.
     * Specialized method for logging network connection information in a consistent format.
     * @param event_type Type of connection event (e.g., "new_connection", "connection_closed")
     * @param connection_data JSON object containing connection details
     */
    void logConnectionEvent(const std::string& event_type, const nlohmann::json& connection_data);
    
    /**
     * Logs firewall rule changes with rule details and optional rule ID.
     * Specialized method for logging firewall rule modifications and operations.
     * @param action Action performed on the rule (e.g., "added", "deleted", "modified")
     * @param rule Rule string or description
     * @param rule_id Optional rule identifier for tracking
     */
    void logRuleChange(const std::string& action, const std::string& rule, std::optional<int> rule_id = std::nullopt);

private:
    /**
     * Converts a LogLevel enum value to its string representation.
     * Used internally for formatting log messages and JSON output.
     * @param level Log level to convert
     * @return String representation of the log level
     */
    std::string levelToString(LogLevel level);
    
    /**
     * Generates an ISO 8601 formatted timestamp with millisecond precision.
     * Creates standardized timestamps for all log entries.
     * @return Formatted timestamp string
     */
    std::string getTimestamp() const;
    
    /**
     * Converts internal LogLevel to syslog priority level.
     * Maps application log levels to appropriate syslog priorities.
     * @param level Application log level
     * @return Corresponding syslog priority value
     */
    int get_syslog_priority(LogLevel level);
    
    /**
     * Sends a formatted message to the system syslog facility.
     * Handles the actual syslog communication and error handling.
     * @param priority Syslog priority level
     * @param message Formatted message to send
     */
    void sendToSyslog(int priority, const std::string& message);

private:
    std::string ident_;
    int syslog_facility_;
    mutable std::mutex mutex_;
};
