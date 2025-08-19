#pragma once

#include <memory>
#include <thread>
#include <atomic>
#include <vector>
#include <functional>
#include <system_error>
#include <chrono>
#include <mutex>

// Forward declarations
class Logger;
struct Connection;

/**
 * ConntrackEventType represents the different types of connection tracking events.
 * These events indicate changes in the state of network connections being monitored.
 */
enum class ConntrackEventType {
    NEW,        ///< New connection established
    UPDATE,     ///< Existing connection updated
    DESTROY,    ///< Connection terminated
    EXPIRED     ///< Connection expired due to timeout
};

/**
 * ConntrackEvent contains information about a connection tracking event.
 * Includes the event type, connection details, and timestamp for event correlation.
 */
struct ConntrackEvent {
    ConntrackEventType type;     ///< Type of connection event
    Connection connection;        ///< Connection data associated with the event
    std::string timestamp;       ///< ISO 8601 timestamp when the event occurred
};

/**
 * MonitorStats tracks performance and operational statistics for the conntrack monitor.
 * Provides insights into monitoring efficiency and connection tracking activity.
 */
struct MonitorStats {
    std::chrono::steady_clock::time_point start_time;    ///< When monitoring started
    std::chrono::steady_clock::time_point last_event_time; ///< Time of last event received
    size_t events_received{0};                           ///< Total events processed
    size_t connections_tracked{0};                        ///< Total connections tracked
    size_t errors_count{0};                              ///< Total errors encountered
};

/**
 * ConntrackMonitor provides real-time monitoring of network connection tracking events.
 * It uses netlink sockets to receive connection state changes from the Linux kernel.
 * The monitor can track new connections, updates, and terminations for security analysis.
 * It maintains a cache of recent events and provides statistics for monitoring purposes.
 */
class ConntrackMonitor {
public:
    /**
     * Constructs a new ConntrackMonitor with the specified logger instance.
     * Initializes the monitor and prepares it for connection tracking operations.
     * @param logger Shared logger instance for recording monitoring events and errors
     */
    explicit ConntrackMonitor(std::shared_ptr<Logger> logger);
    
    /**
     * Destructor that ensures proper cleanup of monitoring resources and stops any ongoing operations.
     * Automatically stops the monitor if it's still running and closes netlink sockets.
     */
    ~ConntrackMonitor();
    
    /**
     * Starts the connection tracking monitor and begins receiving kernel events.
     * Initializes netlink sockets and launches the monitoring thread.
     * @return std::error_code indicating success or failure of startup
     */
    std::error_code start();
    
    /**
     * Stops the connection tracking monitor and terminates all monitoring operations.
     * Gracefully shuts down the monitoring thread and closes netlink connections.
     * @return std::error_code indicating success or failure of shutdown
     */
    std::error_code stop();
    
    /**
     * Sets a callback function to handle connection events from the kernel.
     * Allows external components to receive real-time connection state notifications.
     * @param callback Function to call when connection events occur
     */
    void setConnectionCallback(std::function<void(const Connection&)> callback);
    
    /**
     * Sets a callback function to handle raw conntrack events from the kernel.
     * Provides access to detailed event information including event type and metadata.
     * @param callback Function to call when conntrack events occur
     */
    void setConntrackCallback(std::function<void(const ConntrackEvent&)> callback);
    
    /**
     * Retrieves the most recent connection tracking events from the internal cache.
     * Returns a limited number of recent events for analysis and debugging.
     * @param count Maximum number of events to return
     * @return Vector of recent conntrack events
     */
    std::vector<ConntrackEvent> getRecentEvents(size_t count) const;
    
    /**
     * Retrieves current monitoring statistics and performance metrics.
     * Provides insights into monitoring efficiency and connection tracking activity.
     * @return MonitorStats object containing current statistics
     */
    MonitorStats getStats() const;
    
    /**
     * Checks if the conntrack monitor is currently running and active.
     * @return true if the monitor is running, false otherwise
     */
    bool isRunning() const { return running_.load(); }

private:
    /**
     * Runs the main monitoring loop that continuously processes kernel events.
     * Handles netlink message reception and event parsing in a dedicated thread.
     */
    void monitorLoop();
    
    /**
     * Initializes the netlink socket for receiving conntrack events from the kernel.
     * Sets up socket options, binding, and multicast group membership.
     * @return std::error_code indicating success or failure of socket setup
     */
    std::error_code initializeNetlink();
    
    /**
     * Listens for incoming netlink messages from the kernel.
     * Receives and processes connection tracking events in real-time.
     * @return std::error_code indicating success or failure of message reception
     */
    std::error_code listenForEvents();
    
    /**
     * Parses netlink messages and extracts conntrack event information.
     * Converts raw kernel messages into structured ConntrackEvent objects.
     * @param data Raw netlink message data
     * @param len Length of the message data
     * @return Optional ConntrackEvent object if parsing succeeds, std::nullopt otherwise
     */
    std::optional<ConntrackEvent> parseNetlinkMessage(const void* data, size_t len);
    
    /**
     * Parses conntrack attributes from netlink message payload.
     * Extracts connection details such as IP addresses, ports, and protocol information.
     * @param data Raw attribute data from netlink message
     * @param len Length of the attribute data
     * @param conn Connection object to populate with parsed data
     */
    void parseConntrackAttributes(const void* data, size_t len, Connection& conn);
    
    /**
     * Parses tuple attributes (source/destination information) from conntrack data.
     * Extracts IP addresses, ports, and protocol details for connection endpoints.
     * @param data Raw tuple attribute data
     * @param len Length of the tuple data
     * @param conn Connection object to populate with parsed data
     * @param is_orig Whether this is the original or reply tuple
     */
    void parse_tuple_attributes(const void* data, size_t len, Connection& conn, bool is_orig);
    
    /**
     * Parses protocol-specific information from conntrack attributes.
     * Extracts additional protocol details such as TCP state flags or UDP information.
     * @param data Raw protocol info data
     * @param len Length of the protocol info data
     * @param conn Connection object to populate with parsed data
     */
    void parse_protoinfo_attributes(const void* data, size_t len, Connection& conn);
    
    /**
     * Converts binary IP address data to human-readable string format.
     * Supports both IPv4 and IPv6 address families for connection tracking.
     * @param addr Pointer to binary IP address data
     * @param family Address family (AF_INET or AF_INET6)
     * @return String representation of the IP address
     */
    std::string ipToString(const void* addr, int family) const;
    
    /**
     * Logs error messages with system error codes for debugging purposes.
     * Provides consistent error logging for conntrack monitoring failures.
     * @param message Error description
     * @param ec System error code containing failure details
     */
    void logError(const std::string& message, const std::error_code& ec);

private:
    std::shared_ptr<Logger> logger_;
    std::atomic<bool> running_{false};
    std::atomic<bool> shutdown_requested_{false};
    
    // Netlink socket
    int netlink_socket_;
    
    // Monitoring thread
    std::thread monitor_thread_;
    
    // Event cache and statistics
    std::vector<ConntrackEvent> recent_events_;
    MonitorStats stats_;
    
    // Callbacks
    std::function<void(const Connection&)> connection_callback_;
    std::function<void(const ConntrackEvent&)> conntrack_callback_;
    
    mutable std::mutex cache_mutex_;
    std::vector<ConntrackEvent> events_cache_;
    
    mutable std::mutex stats_mutex_;
    MonitorStats stats_;
};
