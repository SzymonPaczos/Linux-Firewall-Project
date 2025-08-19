#pragma once

#include <memory>
#include <vector>
#include <string>
#include <functional>
#include <system_error>
#include <optional>
#include <chrono>
#include <mutex>

// Forward declarations
class Logger;
struct FirewallRule;
struct Connection;

/**
 * BackendType specifies which firewall backend implementation to use.
 * Determines whether to use iptables or nftables for firewall rule management.
 */
enum class BackendType {
    AUTO,       ///< Automatically detect available backend
    IPTABLES,   ///< Use iptables backend
    NFTABLES    ///< Use nftables backend
};

/**
 * FirewallRule represents a single firewall rule with all its parameters.
 * Contains chain, target, protocol, source, destination, ports, and other rule attributes.
 * Used for creating, modifying, and managing firewall rules through the backend.
 */
struct FirewallRule {
    int id{0};                     ///< Unique rule identifier
    std::string chain;             ///< Firewall chain (INPUT, OUTPUT, FORWARD, etc.)
    std::string target;            ///< Rule target (ACCEPT, DROP, REJECT, etc.)
    std::string protocol;          ///< Network protocol (tcp, udp, icmp, etc.)
    std::string source;            ///< Source IP address or network
    std::string destination;       ///< Destination IP address or network
    std::string ports;             ///< Port specification (single port or range)
    std::string options;           ///< Additional rule options and parameters
    std::string comment;           ///< Optional comment for rule identification
    bool enabled{true};            ///< Whether the rule is currently active
};

/**
 * Connection represents an active network connection being tracked by the firewall.
 * Contains connection details such as IP addresses, ports, protocol, and state information.
 * Used for monitoring and analyzing network traffic patterns.
 */
struct Connection {
    uint64_t id{0};                ///< Unique connection identifier
    std::string protocol;          ///< Network protocol (tcp, udp, icmp, etc.)
    std::string source_ip;         ///< Source IP address
    std::string dest_ip;           ///< Destination IP address
    uint16_t source_port{0};       ///< Source port number
    uint16_t dest_port{0};         ///< Destination port number
    std::string state;             ///< Connection state (ESTABLISHED, NEW, etc.)
    std::string timestamp;         ///< ISO 8601 timestamp when connection was established
};

/**
 * NetfilterBackend provides the low-level firewall management interface using netfilter.
 * It supports both iptables and nftables backends and automatically detects the available system.
 * The backend handles rule creation, deletion, modification, and connection monitoring.
 * It provides a unified API regardless of the underlying firewall implementation being used.
 */
class NetfilterBackend {
public:
    /**
     * Constructs a new NetfilterBackend instance with the specified logger and backend type.
     * Initializes the backend with logging capabilities and sets the preferred firewall implementation.
     * @param logger Shared pointer to the logger instance for error and info logging
     * @param backend Preferred backend type (auto-detection if not specified)
     */
    NetfilterBackend(std::shared_ptr<Logger> logger, BackendType backend = BackendType::AUTO);
    
    /**
     * Destructor that ensures proper cleanup of backend resources and stops any ongoing operations.
     * Logs the backend destruction for debugging purposes.
     */
    ~NetfilterBackend();
    
    /**
     * Initializes the netfilter backend and detects the appropriate firewall implementation.
     * Sets up the backend based on system capabilities and user preferences.
     * @return std::error_code indicating success or failure of initialization
     */
    std::error_code initialize();
    
    /**
     * Retrieves the current list of all firewall rules from the active backend.
     * Returns a vector of FirewallRule objects representing the current firewall configuration.
     * @return Vector of currently active firewall rules
     */
    std::vector<FirewallRule> listRules() const;
    
    /**
     * Adds a new firewall rule to the active backend.
     * Creates the rule according to the specified parameters and adds it to the firewall.
     * @param rule FirewallRule object containing the rule definition
     * @return std::error_code indicating success or failure of the operation
     */
    std::error_code addRule(const FirewallRule& rule);
    
    /**
     * Deletes a firewall rule identified by its unique rule ID.
     * Removes the specified rule from the firewall backend and updates the rule cache.
     * @param rule_id Unique identifier of the rule to delete
     * @return std::error_code indicating success or failure of the operation
     */
    std::error_code deleteRule(int rule_id);
    
    /**
     * Modifies an existing firewall rule with new parameters.
     * Replaces the old rule with the new rule definition while preserving the rule ID.
     * @param rule_id Unique identifier of the rule to modify
     * @param new_rule New rule definition to replace the existing rule
     * @return std::error_code indicating success or failure of the operation
     */
    std::error_code modifyRule(int rule_id, const FirewallRule& new_rule);
    
    /**
     * Enables or disables a firewall rule without removing it.
     * Allows temporary rule deactivation for testing or maintenance purposes.
     * @param rule_id Unique identifier of the rule to toggle
     * @param enabled Whether to enable (true) or disable (false) the rule
     * @return std::error_code indicating success or failure of the operation
     */
    std::error_code toggleRule(int rule_id, bool enabled);
    
    /**
     * Retrieves a specific firewall rule by its unique identifier.
     * Returns the rule details if found, or std::nullopt if the rule doesn't exist.
     * @param rule_id Unique identifier of the rule to retrieve
     * @return Optional FirewallRule object if found, std::nullopt otherwise
     */
    std::optional<FirewallRule> getRule(int rule_id) const;
    
    /**
     * Retrieves the current list of active network connections from the firewall backend.
     * Returns connection information for monitoring and debugging purposes.
     * @return Vector of currently active network connections
     */
    std::vector<Connection> getConnections() const;
    
    /**
     * Sets a callback function to handle connection events from the firewall.
     * Allows external components to receive real-time connection state notifications.
     * @param callback Function to call when connection events occur
     */
    void setConnectionCallback(std::function<void(const Connection&)> callback);
    
    /**
     * Checks if the netfilter backend is currently initialized and ready for operation.
     * @return true if the backend is initialized, false otherwise
     */
    bool isInitialized() const { return initialized_; }
    
    /**
     * Retrieves the currently active backend type being used.
     * Indicates whether iptables or nftables is handling firewall operations.
     * @return BackendType enum value indicating the active backend
     */
    BackendType getBackendType() const { return backend_type_; }

private:
    /**
     * Automatically detects the available firewall backend on the system.
     * Checks for nftables first, then falls back to iptables if available.
     * @return BackendType enum value indicating the detected backend
     */
    BackendType detectBackend();
    
    /**
     * Initializes the iptables backend and verifies its availability.
     * Sets up iptables-specific configurations and validates system support.
     * @return std::error_code indicating success or failure of iptables initialization
     */
    std::error_code initializeIptables();
    
    /**
     * Initializes the nftables backend and verifies its availability.
     * Sets up nftables-specific configurations and validates system support.
     * @return std::error_code indicating success or failure of nftables initialization
     */
    std::error_code initializeNftables();
    
    /**
     * Parses an iptables rule line and converts it to a FirewallRule object.
     * Extracts rule parameters from standard iptables output format.
     * @param rule_line Raw iptables rule line to parse
     * @return FirewallRule object populated with parsed data
     */
    FirewallRule parseIptablesRule(const std::string& rule_line) const;
    
    /**
     * Formats a FirewallRule object into iptables command-line syntax.
     * Creates the appropriate iptables command arguments for rule creation.
     * @param rule FirewallRule object to format
     * @return Formatted iptables rule string
     */
    std::string formatIptablesRule(const FirewallRule& rule) const;
    
    /**
     * Executes an iptables command with the specified arguments.
     * Runs the command in a subprocess and returns the execution result.
     * @param args Vector of command-line arguments for iptables
     * @return std::error_code indicating success or failure of command execution
     */
    std::error_code executeIptablesCommand(const std::vector<std::string>& args);
    
    /**
     * Executes an nft command with the specified arguments.
     * Runs the command in a subprocess and returns the execution result.
     * @param args Vector of command-line arguments for nft
     * @return std::error_code indicating success or failure of command execution
     */
    std::error_code executeNftCommand(const std::vector<std::string>& args);
    
    /**
     * Executes an iptables command and captures its output.
     * Runs the command in a subprocess and returns the command output as a string.
     * @param args Vector of command-line arguments for iptables
     * @return String containing the command output, empty string on failure
     */
    std::string executeIptablesCommandOutput(const std::vector<std::string>& args);
    
    /**
     * Executes an nft command and captures its output.
     * Runs the command in a subprocess and returns the command output as a string.
     * @param args Vector of command-line arguments for nft
     * @return String containing the command output, empty string on failure
     */
    std::string executeNftCommandOutput(const std::vector<std::string>& args);
    
    /**
     * Executes a conntrack command with the specified arguments.
     * Runs the command in a subprocess and returns the execution result.
     * @param args Vector of command-line arguments for conntrack
     * @return std::error_code indicating success or failure of command execution
     */
    std::error_code execute_conntrack_command(const std::vector<std::string>& args);
    
    /**
     * Executes a conntrack command and captures its output.
     * Runs the command in a subprocess and returns the command output as a string.
     * @param args Vector of command-line arguments for conntrack
     * @return String containing the command output, empty string on failure
     */
    std::string execute_conntrack_command_output(const std::vector<std::string>& args);
    
    /**
     * Executes a system command with the specified arguments.
     * Generic command execution function used by all backend-specific command methods.
     * @param command Command name to execute
     * @param args Vector of command-line arguments
     * @return std::error_code indicating success or failure of command execution
     */
    std::error_code execute_command(const std::string& command, const std::vector<std::string>& args);
    
    /**
     * Executes a system command and captures its output.
     * Generic command execution function that captures stdout for output processing.
     * @param args Vector of command-line arguments
     * @return String containing the command output, empty string on failure
     */
    std::string execute_command_output(const std::string& command, const std::vector<std::string>& args);

private:
    std::shared_ptr<Logger> logger_;
    BackendType backend_type_;
    bool initialized_;
    
    // Rule cache for performance
    mutable std::vector<FirewallRule> rules_cache_;
    
    // Connection event callback
    std::function<void(const Connection&)> connection_callback_;
    
    // Mutex for thread safety
    mutable std::mutex mutex_;
    
    std::chrono::steady_clock::time_point last_cache_update_;
};
