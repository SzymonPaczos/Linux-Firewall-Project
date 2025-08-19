#pragma once

#include <memory>
#include <vector>
#include <string>
#include <functional>
#include <system_error>
#include <optional>
#include <nlohmann/json.hpp>

// Forward declarations
class Logger;
class NetfilterBackend;
struct FirewallRule;
struct Connection;

/**
 * FirewallService implements the core firewall management functionality exposed through DBus.
 * It provides methods for adding, deleting, and managing firewall rules, as well as monitoring network connections.
 * The service acts as a bridge between DBus method calls and the underlying netfilter backend implementation.
 * It includes rule validation, parsing, and comprehensive logging of all firewall operations.
 */
class FirewallService {
public:
    /**
     * Constructs a new FirewallService with the specified logger instance.
     * Initializes the service and prepares it for handling firewall management requests.
     * @param logger Shared logger instance for recording firewall operations and errors
     */
    explicit FirewallService(std::shared_ptr<Logger> logger);
    
    /**
     * Destructor that ensures proper cleanup of service resources and stops any ongoing operations.
     * Logs the service destruction for debugging purposes.
     */
    ~FirewallService();
    
    /**
     * Initializes the firewall service and prepares it for operation.
     * Sets up internal state and validates that the service is ready to handle requests.
     * @return std::error_code indicating success or failure of initialization
     */
    std::error_code initialize();
    
    /**
     * Sets the netfilter backend that will handle firewall rule operations.
     * Establishes the connection between the service and the actual firewall implementation.
     * @param backend Pointer to the netfilter backend instance
     */
    void setNetfilterBackend(NetfilterBackend* backend);
    
    /**
     * Sets a callback function to handle signal emissions to DBus clients.
     * Allows the service to notify external applications about firewall events and changes.
     * @param callback Function to call when signals need to be emitted
     */
    void setSignalCallback(std::function<void(const std::string&, const nlohmann::json&)> callback);
    
    /**
     * Retrieves the current list of all firewall rules from the backend.
     * Returns a vector of FirewallRule objects representing the active firewall configuration.
     * @return Vector of currently active firewall rules
     */
    std::vector<FirewallRule> listRules();
    
    /**
     * Adds a new firewall rule based on the provided rule string.
     * Parses the rule string, validates it, and adds it to the firewall backend.
     * @param rule_string String representation of the firewall rule to add
     * @return std::error_code indicating success or failure of the operation
     */
    std::error_code addRule(const std::string& rule_string);
    
    /**
     * Deletes a firewall rule identified by its unique rule ID.
     * Removes the specified rule from the firewall backend and logs the operation.
     * @param rule_id Unique identifier of the rule to delete
     * @return std::error_code indicating success or failure of the operation
     */
    std::error_code deleteRule(int rule_id);
    
    /**
     * Retrieves the current list of active network connections from the firewall backend.
     * Returns connection information for monitoring and debugging purposes.
     * @return Vector of currently active network connections
     */
    std::vector<Connection> getConnections();
    
    /**
     * Emits a connection event signal to notify DBus clients about network connection changes.
     * Formats connection data and sends it through the signal callback mechanism.
     * @param connection Connection data to broadcast to external applications
     */
    void emitConnectionEvent(const Connection& connection);

private:
    /**
     * Parses a rule string and converts it to a FirewallRule object.
     * Supports multiple rule formats including custom delimited and iptables-style syntax.
     * @param rule_string String representation of the firewall rule
     * @return Optional FirewallRule object if parsing succeeds, std::nullopt otherwise
     */
    std::optional<FirewallRule> parseRuleString(const std::string& rule_string);
    
    /**
     * Parses iptables-style rule format and converts it to a FirewallRule object.
     * Handles standard iptables command-line syntax for rule specification.
     * @param rule_string Iptables-formatted rule string
     * @return Optional FirewallRule object if parsing succeeds, std::nullopt otherwise
     */
    std::optional<FirewallRule> parse_iptables_format(const std::string& rule_string);
    
    /**
     * Validates a FirewallRule object to ensure it meets security and syntax requirements.
     * Checks chain names, targets, protocols, and other rule parameters for validity.
     * @param rule FirewallRule object to validate
     * @return true if the rule is valid, false otherwise
     */
    bool validateRule(const FirewallRule& rule);
    
    /**
     * Validates an IP address string for correct format and range.
     * Supports both IPv4 and IPv6 addresses as well as special hostnames.
     * @param ip IP address string to validate
     * @return true if the IP address is valid, false otherwise
     */
    bool is_valid_ip(const std::string& ip);
    
    /**
     * Validates a port number string for correct range and format.
     * Ensures port numbers are within the valid TCP/UDP port range (1-65535).
     * @param port Port number string to validate
     * @return true if the port number is valid, false otherwise
     */
    bool is_valid_port(const std::string& port);
    
    /**
     * Formats a FirewallRule object into a human-readable string representation.
     * Creates a standardized format for displaying and logging firewall rules.
     * @param rule FirewallRule object to format
     * @return Formatted string representation of the rule
     */
    std::string format_rule_string(const FirewallRule& rule);
    
    /**
     * Logs firewall rule operations for auditing and debugging purposes.
     * Records the action performed, rule details, and optional rule identifier.
     * @param operation Type of operation performed (e.g., "added", "deleted")
     * @param rule Rule string or description
     * @param rule_id Optional rule identifier for tracking
     */
    void logRuleOperation(const std::string& operation, const std::string& rule, std::optional<int> rule_id = std::nullopt);
    
    /**
     * Logs error messages with system error codes for debugging purposes.
     * Provides consistent error logging for firewall service failures.
     * @param message Error description
     * @param ec System error code containing failure details
     */
    void logError(const std::string& message, const std::error_code& ec);

private:
    std::shared_ptr<Logger> logger_;
    NetfilterBackend* netfilter_backend_;
    
    bool initialized_{false};
    std::function<void(const std::string&, const nlohmann::json&)> signal_callback_;
};
