#include "FirewallService.h"
#include "Logger.h"
#include <iostream>
#include <sstream>
#include <regex>

FirewallService::FirewallService(std::shared_ptr<Logger> logger) 
    : logger_(logger), netfilter_backend_(nullptr) {
    if (logger_) {
        logger_->log(Logger::LogLevel::INFO, "FirewallService created.");
    }
}

FirewallService::~FirewallService() {
    if (logger_) {
        logger_->log(Logger::LogLevel::INFO, "FirewallService destroyed.");
    }
}

std::error_code FirewallService::initialize() {
    try {
        if (logger_) {
            logger_->log(Logger::LogLevel::INFO, "Initialization of FirewallService...");
        }
        
        // Check if backend is available
        if (!netfilter_backend_ || !netfilter_backend_->isInitialized()) {
            if (logger_) {
                logger_->log(Logger::LogLevel::ERROR, "Firewall backend is not available");
            }
            return std::make_error_code(std::errc::operation_canceled);
        }
        
        initialized_ = true;
        if (logger_) {
            logger_->log(Logger::LogLevel::INFO, "FirewallService initialized successfully");
        }
        return std::error_code{};
        
    } catch (const std::exception& e) {
        if (logger_) {
            logger_->log(Logger::LogLevel::ERROR, "Critical error during initialization: " + std::string(e.what()));
        }
        return std::make_error_code(std::errc::operation_canceled);
    }
}

void FirewallService::setNetfilterBackend(NetfilterBackend* backend) {
    netfilter_backend_ = backend;
    if (logger_) {
        logger_->log(Logger::LogLevel::INFO, "NetfilterBackend set in FirewallService");
    }
}

void FirewallService::setSignalCallback(std::function<void(const std::string&, const nlohmann::json&)> callback) {
    signal_callback_ = std::move(callback);
}

std::vector<FirewallRule> FirewallService::listRules() {
    try {
        if (!netfilter_backend_ || !netfilter_backend_->isInitialized()) {
            if (logger_) {
                logger_->log(Logger::LogLevel::ERROR, "Firewall backend is not available");
            }
            return {};
        }
        
        auto rules = netfilter_backend_->listRules();
        
        // Log operation
        nlohmann::json data;
        data["rule_count"] = rules.size();
        logger_->log(Logger::LogLevel::INFO, "Firewall rules list retrieved", data);
        
        return rules;
        
    } catch (const std::exception& e) {
        if (logger_) {
            logger_->log(Logger::LogLevel::ERROR, "Error while retrieving rules list: " + std::string(e.what()));
        }
        return {};
    }
}

std::error_code FirewallService::addRule(const std::string& rule_string) {
    try {
        if (!netfilter_backend_ || !netfilter_backend_->isInitialized()) {
            if (logger_) {
                logger_->log(Logger::LogLevel::ERROR, "Firewall backend is not available");
            }
            return std::make_error_code(std::errc::operation_canceled);
        }
        
        if (logger_) {
            logger_->log(Logger::LogLevel::INFO, "Adding rule: " + rule_string);
        }
        
                 // Parse rule
        auto rule = parseRuleString(rule_string);
        if (!rule) {
            if (logger_) {
                logger_->log(Logger::LogLevel::ERROR, "Invalid rule format: " + rule_string);
            }
            return std::make_error_code(std::errc::invalid_argument);
        }
        
        // Validate rule
        if (!validateRule(*rule)) {
            if (logger_) {
                logger_->log(Logger::LogLevel::ERROR, "Rule validation failed: " + rule_string);
            }
            return std::make_error_code(std::errc::invalid_argument);
        }
        
        // Add rule
        auto ec = netfilter_backend_->addRule(*rule);
        if (ec) {
            if (logger_) {
                logger_->log(Logger::LogLevel::ERROR, "Error while adding rule", ec);
            }
            return ec;
        }
        
        if (logger_) {
            logger_->log(Logger::LogLevel::INFO, "Rule added successfully");
        }
        
        return std::error_code{};
        
    } catch (const std::exception& e) {
        if (logger_) {
            logger_->log(Logger::LogLevel::ERROR, "Critical error while adding rule: " + std::string(e.what()));
        }
        return std::make_error_code(std::errc::operation_canceled);
    }
}

std::error_code FirewallService::deleteRule(int rule_id) {
    try {
        if (!netfilter_backend_ || !netfilter_backend_->isInitialized()) {
            if (logger_) {
                logger_->log(Logger::LogLevel::ERROR, "Firewall backend is not available");
            }
            return std::make_error_code(std::errc::operation_canceled);
        }
        
        if (logger_) {
            logger_->log(Logger::LogLevel::INFO, "Removing rule with ID: " + std::to_string(rule_id));
        }
        
        // Sprawdź czy reguła istnieje
        auto rule = netfilter_backend_->getRule(rule_id);
        if (!rule) {
            return std::make_error_code(std::errc::no_such_file_or_directory);
        }
        
        // Usuń regułę
        auto ec = netfilter_backend_->deleteRule(rule_id);
        if (ec) {
            if (logger_) {
                logger_->log(Logger::LogLevel::ERROR, "Error while removing rule", ec);
            }
            return ec;
        }
        
        if (logger_) {
            logger_->log(Logger::LogLevel::INFO, "Rule removed successfully");
        }
        
        return std::error_code{};
        
    } catch (const std::exception& e) {
        if (logger_) {
            logger_->log(Logger::LogLevel::ERROR, "Critical error while removing rule: " + std::string(e.what()));
        }
        return std::make_error_code(std::errc::operation_canceled);
    }
}

std::vector<Connection> FirewallService::getConnections() {
    try {
        if (!netfilter_backend_ || !netfilter_backend_->isInitialized()) {
            if (logger_) {
                logger_->log(Logger::LogLevel::ERROR, "Firewall backend is not available");
            }
            return {};
        }
        
        auto connections = netfilter_backend_->getConnections();
        
        // Log operation
        nlohmann::json data;
        data["connection_count"] = connections.size();
        if (logger_) {
            logger_->log(Logger::LogLevel::INFO, "Connections list retrieved", data);
        }
        
        return connections;
        
    } catch (const std::exception& e) {
        if (logger_) {
            logger_->log(Logger::LogLevel::ERROR, "Error while retrieving connections list: " + std::string(e.what()));
        }
        return {};
    }
}

void FirewallService::emitConnectionEvent(const Connection& connection) {
    try {
        if (!signal_callback_) {
            return;
        }
        
        // Przygotuj dane połączenia
        nlohmann::json conn_data;
        conn_data["id"] = connection.id;
        conn_data["protocol"] = connection.protocol;
        conn_data["source_ip"] = connection.source_ip;
        conn_data["dest_ip"] = connection.dest_ip;
        conn_data["source_port"] = connection.source_port;
        conn_data["dest_port"] = connection.dest_port;
        conn_data["state"] = connection.state;
        conn_data["timestamp"] = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        
        // Emituj sygnał
        signal_callback_("connection_event", conn_data);
        
        // Loguj zdarzenie
        if (logger_) {
            logger_->logConnectionEvent("connection_event_emitted", conn_data);
        }
        
    } catch (const std::exception& e) {
        if (logger_) {
            logger_->log(Logger::LogLevel::ERROR, "Error while emitting connection event: " + std::string(e.what()));
        }
    }
}

std::optional<FirewallRule> FirewallService::parseRuleString(const std::string& rule_string) {
    try {
        FirewallRule rule;
        
        // Przykład parsowania prostego formatu: "chain:target:protocol:source:destination:ports"
        std::istringstream iss(rule_string);
        std::string token;
        std::vector<std::string> tokens;
        
        while (std::getline(iss, token, ':')) {
            tokens.push_back(token);
        }
        
        if (tokens.size() >= 2) {
            rule.chain = tokens[0];
            rule.target = tokens[1];
            
            if (tokens.size() >= 3) rule.protocol = tokens[2];
            if (tokens.size() >= 4) rule.source = tokens[3];
            if (tokens.size() >= 5) rule.destination = tokens[4];
            if (tokens.size() >= 6) rule.ports = tokens[5];
            
            // Generuj unikalne ID
            static int next_id = 1;
            rule.id = next_id++;
            
            return rule;
        }
        
        // Alternatywnie, spróbuj parsować format iptables
        return parse_iptables_format(rule_string);
        
    } catch (const std::exception& e) {
        if (logger_) {
            logger_->log(Logger::LogLevel::ERROR, "Rule parsing error: " + std::string(e.what()));
        }
        return std::nullopt;
    }
}

std::optional<FirewallRule> FirewallService::parse_iptables_format(const std::string& rule_string) {
    try {
        FirewallRule rule;
        
        // Przykład parsowania formatu iptables: "-A INPUT -p tcp --dport 80 -j ACCEPT"
        std::istringstream iss(rule_string);
        std::string token;
        std::vector<std::string> tokens;
        
        while (iss >> token) {
            tokens.push_back(token);
        }
        
        if (tokens.size() < 3) {
            return std::nullopt;
        }
        
        // Parsuj akcję i łańcuch
        if (tokens[0] == "-A" && tokens.size() > 1) {
            rule.chain = tokens[1];
        } else if (tokens[0] == "-I" && tokens.size() > 1) {
            rule.chain = tokens[1];
        } else {
            return std::nullopt;
        }
        
        // Parsuj pozostałe parametry
        for (size_t i = 2; i < tokens.size(); ++i) {
            if (tokens[i] == "-p" && i + 1 < tokens.size()) {
                rule.protocol = tokens[++i];
            } else if (tokens[i] == "-s" && i + 1 < tokens.size()) {
                rule.source = tokens[++i];
            } else if (tokens[i] == "-d" && i + 1 < tokens.size()) {
                rule.destination = tokens[++i];
            } else if (tokens[i] == "--dport" && i + 1 < tokens.size()) {
                rule.ports = tokens[++i];
            } else if (tokens[i] == "-j" && i + 1 < tokens.size()) {
                rule.target = tokens[++i];
            }
        }
        
        // Generuj unikalne ID
        static int next_id = 1;
        rule.id = next_id++;
        
        return rule;
        
    } catch (const std::exception& e) {
        if (logger_) {
            logger_->log(Logger::LogLevel::ERROR, "iptables format parsing error: " + std::string(e.what()));
        }
        return std::nullopt;
    }
}

bool FirewallService::validateRule(const FirewallRule& rule) {
    // Sprawdź czy łańcuch jest prawidłowy
    if (rule.chain.empty() || rule.target.empty()) {
        return false;
    }
    
    // Sprawdź czy łańcuch jest standardowy
    std::vector<std::string> valid_chains = {"INPUT", "OUTPUT", "FORWARD", "PREROUTING", "POSTROUTING"};
    bool valid_chain = false;
    for (const auto& valid : valid_chains) {
        if (rule.chain == valid) {
            valid_chain = true;
            break;
        }
    }
    
    if (!valid_chain) {
        return false;
    }
    
    // Sprawdź czy target jest prawidłowy
    std::vector<std::string> valid_targets = {"ACCEPT", "DROP", "REJECT", "LOG", "RETURN"};
    bool valid_target = false;
    for (const auto& valid : valid_targets) {
        if (rule.target == valid) {
            valid_target = true;
            break;
        }
    }
    
    if (!valid_target) {
        return false;
    }
    
    // Sprawdź protokół jeśli podano
    if (!rule.protocol.empty()) {
        std::vector<std::string> valid_protocols = {"tcp", "udp", "icmp", "icmpv6"};
        bool valid_protocol = false;
        for (const auto& valid : valid_protocols) {
            if (rule.protocol == valid) {
                valid_protocol = true;
                break;
            }
        }
        
        if (!valid_protocol) {
            return false;
        }
    }
    
    // Sprawdź adresy IP jeśli podano
    if (!rule.source.empty() && !is_valid_ip(rule.source)) {
        return false;
    }
    
    if (!rule.destination.empty() && !is_valid_ip(rule.destination)) {
        return false;
    }
    
    // Sprawdź porty jeśli podano
    if (!rule.ports.empty() && !is_valid_port(rule.ports)) {
        return false;
    }
    
    return true;
}

bool FirewallService::is_valid_ip(const std::string& ip) {
    // Prosta walidacja adresu IP
    std::regex ipv4_regex(R"(^(\d{1,3}\.){3}\d{1,3}$)");
    std::regex ipv6_regex(R"(^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$)");
    
    if (std::regex_match(ip, ipv4_regex)) {
        // Sprawdź zakresy IPv4
        std::istringstream iss(ip);
        std::string token;
        while (std::getline(iss, token, '.')) {
            int octet = std::stoi(token);
            if (octet < 0 || octet > 255) {
                return false;
            }
        }
        return true;
    }
    
    if (std::regex_match(ip, ipv6_regex)) {
        return true;
    }
    
    // Sprawdź czy to nie jest nazwa hosta
    if (ip == "localhost" || ip == "any" || ip == "0.0.0.0") {
        return true;
    }
    
    return false;
}

bool FirewallService::is_valid_port(const std::string& port) {
    try {
        int port_num = std::stoi(port);
        return port_num >= 1 && port_num <= 65535;
    } catch (...) {
        return false;
    }
}

std::string FirewallService::format_rule_string(const FirewallRule& rule) {
    std::ostringstream oss;
    
    oss << rule.chain << ":" << rule.target;
    
    if (!rule.protocol.empty()) {
        oss << ":" << rule.protocol;
    } else {
        oss << ":any";
    }
    
    if (!rule.source.empty()) {
        oss << ":" << rule.source;
    } else {
        oss << ":any";
    }
    
    if (!rule.destination.empty()) {
        oss << ":" << rule.destination;
    } else {
        oss << ":any";
    }
    
    if (!rule.ports.empty()) {
        oss << ":" << rule.ports;
    } else {
        oss << ":any";
    }
    
    return oss.str();
}

void FirewallService::logRuleOperation(const std::string& operation, const std::string& rule, std::optional<int> rule_id) {
            logger_->logRuleChange(operation, rule, rule_id);
}

void FirewallService::logError(const std::string& message, const std::error_code& ec) {
    logger_->logError(message, ec);
}
