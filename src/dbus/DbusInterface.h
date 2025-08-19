#pragma once

#include <memory>
#include <functional>
#include <system_error>
#include <atomic>

// Forward declarations
class Logger;
class NetfilterBackend;
class FirewallService;
struct Connection;

/**
 * DbusInterface manages the DBus communication layer for the firewall daemon.
 * It provides a high-level interface for external applications to interact with the firewall through DBus.
 * The class handles DBus connection management, service registration, and message routing to the FirewallService.
 * It acts as the primary external API gateway for firewall management operations.
 */
class DbusInterface {
public:
    /**
     * Constructs a new DbusInterface with the specified logger instance.
     * Initializes internal state and prepares for DBus communication setup.
     * @param logger Shared logger instance for recording DBus operations and errors
     */
    explicit DbusInterface(std::shared_ptr<Logger> logger);
    
    /**
     * Destructor that ensures proper cleanup of DBus resources and stops any running operations.
     * Automatically stops the interface if it's still running.
     */
    ~DbusInterface();
    
    /**
     * Initializes the DBus interface by establishing connections and registering services.
     * Sets up the FirewallService and prepares for incoming DBus method calls.
     * @return std::error_code indicating success or failure of initialization
     */
    std::error_code initialize();
    
    /**
     * Starts the DBus message processing loop and begins accepting method calls.
     * Launches the main DBus event handling thread and starts processing messages.
     * @return std::error_code indicating success or failure of startup
     */
    std::error_code run();
    
    /**
     * Stops the DBus interface and terminates all message processing.
     * Gracefully shuts down the DBus loop and cleans up resources.
     * @return std::error_code indicating success or failure of shutdown
     */
    std::error_code stop();
    
    /**
     * Sets the netfilter backend that will handle firewall rule operations.
     * Establishes the connection between DBus interface and the actual firewall implementation.
     * @param backend Pointer to the netfilter backend instance
     */
    void setNetfilterBackend(NetfilterBackend* backend);
    
    /**
     * Sets a callback function to handle connection events from the firewall.
     * Allows the DBus interface to notify external applications about network connection changes.
     * @param callback Function to call when connection events occur
     */
    void setConnectionCallback(std::function<void(const Connection&)> callback);
    
    /**
     * Emits a connection event signal to DBus subscribers.
     * Broadcasts network connection information to all listening DBus clients.
     * @param connection Connection data to broadcast
     */
    void emitConnectionEvent(const Connection& connection);
    
    /**
     * Checks if the DBus interface is currently running and processing messages.
     * @return true if the interface is active, false otherwise
     */
    bool isRunning() const { return running_; }

private:
    /**
     * Initializes the DBus connection and establishes communication with the system bus.
     * Sets up the basic DBus infrastructure required for service operation.
     * @return std::error_code indicating success or failure of connection setup
     */
    std::error_code initializeConnection();
    
    /**
     * Registers the firewall service on the DBus system bus.
     * Makes the firewall methods available to external DBus clients.
     * @return std::error_code indicating success or failure of service registration
     */
    std::error_code registerService();
    
    /**
     * Runs the main DBus message processing loop.
     * Continuously processes incoming DBus method calls and signals.
     */
    void dbusLoop();
    
    /**
     * Handles individual DBus messages and routes them to appropriate handlers.
     * Processes method calls, signals, and other DBus message types.
     */
    void handleDbusMessage();
    
    /**
     * Logs error messages with system error codes for debugging purposes.
     * Provides consistent error logging for DBus-related failures.
     * @param message Error description
     * @param ec System error code containing failure details
     */
    void logError(const std::string& message, const std::error_code& ec);

private:
    std::shared_ptr<Logger> logger_;
    std::unique_ptr<FirewallService> firewall_service_;
    
    std::atomic<bool> initialized_{false};
    std::atomic<bool> running_{false};
    
    // DBus connection (placeholder for actual implementation)
    void* connection_;
    
    std::function<void(const Connection&)> connection_callback_;
};
