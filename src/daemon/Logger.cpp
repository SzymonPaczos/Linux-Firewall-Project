#include "Logger.h"
#include <iostream>
#include <sstream>
#include <syslog.h>
#include <chrono>
#include <iomanip>
#include <cstring>

Logger::Logger(const std::string& ident) 
    : ident_(ident), syslog_facility_(LOG_DAEMON) {
    // Open syslog
    openlog(ident_.c_str(), LOG_PID | LOG_CONS, syslog_facility_);
}

Logger::~Logger() {
    try {
        closelog();
    } catch (...) {
        // Ignore errors during closing
    }
}

void Logger::log(LogLevel level, const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Create JSON message
    nlohmann::json log_entry;
    log_entry["timestamp"] = getTimestamp();
    log_entry["level"] = levelToString(level);
    log_entry["message"] = message;
    log_entry["ident"] = ident_;
    
    // Send to syslog
    int priority = get_syslog_priority(level);
    sendToSyslog(priority, log_entry.dump());
}

void Logger::log(LogLevel level, const std::string& message, const nlohmann::json& data) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Create JSON message
    nlohmann::json log_entry;
    log_entry["timestamp"] = getTimestamp();
    log_entry["level"] = levelToString(level);
    log_entry["message"] = message;
    log_entry["ident"] = ident_;
    log_entry["data"] = data;
    
    // Send to syslog
    int priority = get_syslog_priority(level);
    sendToSyslog(priority, log_entry.dump());
}

void Logger::logError(const std::string& message, const std::error_code& ec) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Create JSON message
    nlohmann::json log_entry;
    log_entry["timestamp"] = getTimestamp();
    log_entry["level"] = "ERROR";
    log_entry["message"] = message;
    log_entry["ident"] = ident_;
    log_entry["error_code"] = ec.value();
    log_entry["error_message"] = ec.message();
    log_entry["error_category"] = ec.category().name();
    
    // Send to syslog
    sendToSyslog(LOG_ERR, log_entry.dump());
}

void Logger::logConnectionEvent(const std::string& event_type, const nlohmann::json& connection_data) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Create JSON message
    nlohmann::json log_entry;
    log_entry["timestamp"] = getTimestamp();
    log_entry["level"] = "INFO";
    log_entry["message"] = "Connection event: " + event_type;
    log_entry["ident"] = ident_;
    log_entry["event_type"] = event_type;
    log_entry["connection"] = connection_data;
    
    // Send to syslog
    sendToSyslog(LOG_INFO, log_entry.dump());
}

void Logger::logRuleChange(const std::string& action, const std::string& rule, std::optional<int> rule_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Create JSON message
    nlohmann::json log_entry;
    log_entry["timestamp"] = getTimestamp();
    log_entry["level"] = "INFO";
    log_entry["message"] = "Firewall rule " + action;
    log_entry["ident"] = ident_;
    log_entry["action"] = action;
    log_entry["rule"] = rule;
    if (rule_id.has_value()) {
        log_entry["rule_id"] = rule_id.value();
    }
    
    // Send to syslog
    sendToSyslog(LOG_INFO, log_entry.dump());
}

std::string Logger::levelToString(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG:   return "DEBUG";
        case LogLevel::INFO:    return "INFO";
        case LogLevel::WARNING: return "WARNING";
        case LogLevel::ERROR:   return "ERROR";
        case LogLevel::CRITICAL: return "CRITICAL";
        default:                return "UNKNOWN";
    }
}

std::string Logger::getTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
    
    return ss.str();
}

int Logger::get_syslog_priority(LogLevel level) {
    switch (level) {
        case LogLevel::DEBUG:   return LOG_DEBUG;
        case LogLevel::INFO:    return LOG_INFO;
        case LogLevel::WARNING: return LOG_WARNING;
        case LogLevel::ERROR:   return LOG_ERR;
        case LogLevel::CRITICAL: return LOG_CRIT;
        default:                return LOG_INFO;
    }
}

void Logger::sendToSyslog(int priority, const std::string& message) {
    try {
        // Send to syslog
        syslog(priority, "%s", message.c_str());
        
        // Additionally send to stderr if in debug mode
        #ifdef DEBUG
        std::cerr << "[" << levelToString(static_cast<LogLevel>(priority)) 
                  << "] " << message << std::endl;
        #endif
        
    } catch (const std::exception& e) {
        // In case of error, try to send simple message
        try {
            syslog(LOG_ERR, "Logger error: %s", e.what());
        } catch (...) {
            // Finally ignore error
        }
    }
}
