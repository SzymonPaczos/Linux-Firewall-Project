#pragma once

#include <memory>
#include <thread>
#include <atomic>
#include <functional>
#include <system_error>
#include <chrono>

// Forward declarations
class Logger;
class NetfilterBackend;
class DbusInterface;
class ConntrackMonitor;
struct Connection;

/**
 * DaemonCore is the central orchestrator class that manages the entire firewall daemon lifecycle.
 * It coordinates all major components including the netfilter backend, DBus interface, and conntrack monitoring.
 * The class handles initialization, startup, shutdown, and provides the main event loop for the daemon.
 * It acts as the bridge between different subsystems and manages their communication and state.
 */
class DaemonCore {
public:
    /**
     * Constructs a new DaemonCore instance and initializes all required components.
     * Sets up the logger, netfilter backend, DBus interface, and conntrack monitor.
     */
    DaemonCore();
    
    /**
     * Destructor that ensures proper cleanup of all components and threads.
     * Stops the daemon if it's still running and cleans up resources.
     */
    ~DaemonCore();
    
    /**
     * Starts the daemon by initializing all components and launching the main event loop.
     * @return std::error_code indicating success or failure of the startup process
     */
    std::error_code start();
    
    /**
     * Stops the daemon gracefully by shutting down all components and waiting for threads to finish.
     * @return std::error_code indicating success or failure of the shutdown process
     */
    std::error_code stop();
    
    /**
     * Sets a callback function to handle system signals received by the daemon.
     * @param handler Function that will be called when a signal is received
     */
    void setSignalHandler(std::function<void(int)> handler);
    
    /**
     * Checks if the daemon is currently running and active.
     * @return true if the daemon is running, false otherwise
     */
    bool isRunning() const { return running_.load(); }
    
    /**
     * Reports daemon status to systemd (if running under systemd).
     * Should be called when daemon is ready to serve requests.
     */
    void reportReadyToSystemd();
    
    /**
     * Reports daemon status to systemd (if running under systemd).
     * Should be called when daemon is stopping.
     */
    void reportStoppingToSystemd();

private:
    /**
     * Initializes all daemon components including netfilter backend, DBus interface, and conntrack monitor.
     * Sets up callbacks and establishes communication between components.
     * @return std::error_code indicating success or failure of initialization
     */
    std::error_code initializeComponents();
    
    /**
     * Runs the main daemon loop that monitors component health and manages the overall daemon state.
     * Launches DBus processing in a separate thread and maintains the main control loop.
     */
    void runMainLoop();
    
    /**
     * Sets up signal handling for the daemon process.
     * Configures handlers for SIGTERM, SIGINT, and other relevant signals.
     */
    void setupSignalHandling();
    
    /**
     * Shuts down all daemon components in the correct order.
     * Stops the conntrack monitor and DBus interface, then cleans up resources.
     */
    void shutdownComponents();

private:
    std::unique_ptr<Logger> logger_;
    std::unique_ptr<NetfilterBackend> netfilter_;
    std::unique_ptr<DbusInterface> dbus_;
    std::unique_ptr<ConntrackMonitor> conntrack_;
    
    std::thread main_thread_;
    std::thread dbus_thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> shutdown_requested_{false};
    
    std::function<void(int)> signal_handler_;
    std::function<void(const Connection&)> connection_callback_;
};
