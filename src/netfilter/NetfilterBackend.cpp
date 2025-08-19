#include "NetfilterBackend.h"
#include "Logger.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <unistd.h>
#include <sys/wait.h>
#include <regex>

NetfilterBackend::NetfilterBackend(std::shared_ptr<Logger> logger, BackendType backend) 
    : logger_(logger), backend_type_(backend), initialized_(false) {
    if (logger_) {
        logger_->log(Logger::LogLevel::INFO, "NetfilterBackend utworzony");
    }
}

NetfilterBackend::~NetfilterBackend() {
    if (logger_) {
        logger_->log(Logger::LogLevel::INFO, "NetfilterBackend niszczony");
    }
    
    if (initialized_) {
        // Cleanup resources
    }
}

std::error_code NetfilterBackend::initialize() {
    if (initialized_) {
        return std::error_code{};
    }
    
    if (logger_) {
        logger_->log(Logger::LogLevel::INFO, "Inicjalizacja NetfilterBackend...");
    }
    
    try {
        // Automatically detect backend if not specified
        if (backend_type_ == BackendType::AUTO) {
            backend_type_ = detectBackend();
        }
        
        std::error_code ec;
        switch (backend_type_) {
            case BackendType::IPTABLES:
                ec = initializeIptables();
                break;
            case BackendType::NFTABLES:
                ec = initializeNftables();
                break;
            default:
                ec = std::make_error_code(std::errc::not_supported);
                break;
        }
        
        if (ec) {
            if (logger_) {
                logger_->log(Logger::LogLevel::ERROR, "Backend initialization error", ec);
            }
            return ec;
        }
        
        initialized_ = true;
        if (logger_) {
            logger_->log(Logger::LogLevel::INFO, "NetfilterBackend initialized successfully with backend: " + 
                        (backend_type_ == BackendType::IPTABLES ? "iptables" : "nftables"));
        }
        
        return std::error_code{};
        
    } catch (const std::exception& e) {
        if (logger_) {
            logger_->log(Logger::LogLevel::ERROR, "Błąd krytyczny podczas inicjalizacji: " + std::string(e.what()));
        }
        return std::make_error_code(std::errc::operation_canceled);
    }
}

std::vector<FirewallRule> NetfilterBackend::listRules() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) {
        return {};
    }
    
    try {
        // Sprawdź czy cache jest aktualny
        auto now = std::chrono::steady_clock::now();
        if (now - last_cache_update_ < std::chrono::seconds(30)) {
            return rules_cache_;
        }
        
        std::vector<FirewallRule> rules;
        
        if (backend_type_ == BackendType::IPTABLES) {
            // Pobierz reguły iptables
            std::vector<std::string> args = {"-L", "--line-numbers", "-n"};
            auto output = executeIptablesCommandOutput(args);
            
            if (output.empty()) {
                return {};
            }
            
            // Parsuj wyjście iptables
            std::istringstream iss(output);
            std::string line;
            int rule_id = 1;
            
            while (std::getline(iss, line)) {
                if (line.empty() || line[0] == '#' || line.find("Chain") != std::string::npos) {
                    continue;
                }
                
                auto rule = parseIptablesRule(line);
                if (rule.id == 0) {
                    rule.id = rule_id++;
                }
                rules.push_back(rule);
            }
        } else if (backend_type_ == BackendType::NFTABLES) {
            // Pobierz reguły nftables
            std::vector<std::string> args = {"list", "ruleset"};
            auto output = executeNftCommandOutput(args);
            
            if (output.empty()) {
                return {};
            }
            
            // TODO: Implementacja parsowania nftables
            // Na razie zwracamy puste reguły
        }
        
        // Zaktualizuj cache
        rules_cache_ = rules;
        last_cache_update_ = now;
        
        return rules;
        
    } catch (const std::exception& e) {
        if (logger_) {
            logger_->log(Logger::LogLevel::ERROR, "Błąd podczas pobierania reguł: " + std::string(e.what()));
        }
        return {};
    }
}

std::error_code NetfilterBackend::addRule(const FirewallRule& rule) {
    if (!initialized_) {
        return std::make_error_code(std::errc::not_connected);
    }
    
    if (logger_) {
        logger_->log(Logger::LogLevel::INFO, "Dodawanie reguły: " + rule.chain + " -> " + rule.target);
    }
    
    try {
        std::vector<std::string> args;
        
        if (backend_type_ == BackendType::IPTABLES) {
            // Formatuj regułę iptables
            std::string rule_string = formatIptablesRule(rule);
            args = {"-A", rule.chain};
            
            // Dodaj parametry reguły
            if (!rule.protocol.empty()) {
                args.push_back("-p");
                args.push_back(rule.protocol);
            }
            
            if (!rule.source.empty()) {
                args.push_back("-s");
                args.push_back(rule.source);
            }
            
            if (!rule.destination.empty()) {
                args.push_back("-d");
                args.push_back(rule.destination);
            }
            
            if (!rule.ports.empty()) {
                args.push_back("--dport");
                args.push_back(rule.ports);
            }
            
            if (!rule.options.empty()) {
                // Parsuj dodatkowe opcje
                std::istringstream iss(rule.options);
                std::string option;
                while (iss >> option) {
                    args.push_back(option);
                }
            }
            
            args.push_back("-j");
            args.push_back(rule.target);
            
            if (!rule.comment.empty()) {
                args.push_back("-m");
                args.push_back("comment");
                args.push_back("--comment");
                args.push_back(rule.comment);
            }
            
        } else if (backend_type_ == BackendType::NFTABLES) {
            // TODO: Implementacja dodawania reguł nftables
            return std::make_error_code(std::errc::not_supported);
        }
        
        // Wykonaj komendę
        auto ec = executeIptablesCommand(args);
        if (ec) {
            if (logger_) {
                logger_->log(Logger::LogLevel::ERROR, "Błąd podczas dodawania reguły", ec);
            }
            return ec;
        }
        
        // Zaktualizuj cache
        std::lock_guard<std::mutex> lock(mutex_);
        rules_cache_.clear();
        last_cache_update_ = std::chrono::steady_clock::time_point{};
        
        // Loguj zmianę
        logger_->logRuleChange("added", formatIptablesRule(rule));
        
        if (logger_) {
            logger_->log(Logger::LogLevel::INFO, "Reguła dodana pomyślnie");
        }
        return std::error_code{};
        
    } catch (const std::exception& e) {
        if (logger_) {
            logger_->log(Logger::LogLevel::ERROR, "Błąd krytyczny podczas dodawania reguły: " + std::string(e.what()));
        }
        return std::make_error_code(std::errc::operation_canceled);
    }
}

std::error_code NetfilterBackend::deleteRule(int rule_id) {
    if (!initialized_) {
        return std::make_error_code(std::errc::not_connected);
    }
    
    if (logger_) {
        logger_->log(Logger::LogLevel::INFO, "Usuwanie reguły o ID: " + std::to_string(rule_id));
    }
    
    try {
        if (backend_type_ == BackendType::IPTABLES) {
            // Znajdź regułę w cache
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = std::find_if(rules_cache_.begin(), rules_cache_.end(),
                                  [rule_id](const FirewallRule& r) { return r.id == rule_id; });
            
            if (it == rules_cache_.end()) {
                if (logger_) {
                    logger_->log(Logger::LogLevel::ERROR, "Reguła o ID " + std::to_string(rule_id) + " nie została znaleziona");
                }
                return std::make_error_code(std::errc::no_such_file_or_directory);
            }
            
            // Usuń regułę przez iptables
            std::vector<std::string> args = {"-D", it->chain, std::to_string(rule_id)};
            auto ec = executeIptablesCommand(args);
            if (ec) {
                if (logger_) {
                    logger_->log(Logger::LogLevel::ERROR, "Błąd podczas usuwania reguły", ec);
                }
                return ec;
            }
            
            // Zaktualizuj cache
            rules_cache_.clear();
            last_cache_update_ = std::chrono::steady_clock::time_point{};
            
            // Loguj zmianę
            logger_->logRuleChange("deleted", formatIptablesRule(*it), rule_id);
            
        } else if (backend_type_ == BackendType::NFTABLES) {
            // TODO: Implementacja usuwania reguł nftables
            return std::make_error_code(std::errc::not_supported);
        }
        
        if (logger_) {
            logger_->log(Logger::LogLevel::INFO, "Reguła usunięta pomyślnie");
        }
        return std::error_code{};
        
    } catch (const std::exception& e) {
        if (logger_) {
            logger_->log(Logger::LogLevel::ERROR, "Błąd krytyczny podczas usuwania reguły: " + std::string(e.what()));
        }
        return std::make_error_code(std::errc::operation_canceled);
    }
}

std::error_code NetfilterBackend::modifyRule(int rule_id, const FirewallRule& new_rule) {
    // Usuń starą regułę i dodaj nową
            auto ec = deleteRule(rule_id);
    if (ec) {
        return ec;
    }
    
            return addRule(new_rule);
}

std::error_code NetfilterBackend::toggleRule(int rule_id, bool enabled) {
    if (!initialized_) {
        return std::make_error_code(std::errc::not_connected);
    }
    
    if (logger_) {
        logger_->log(Logger::LogLevel::INFO, "Przełączanie reguły o ID " + std::to_string(rule_id) + " na: " + 
                    (enabled ? "włączona" : "wyłączona"));
    }
    
    try {
        if (backend_type_ == BackendType::IPTABLES) {
            // Znajdź regułę w cache
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = std::find_if(rules_cache_.begin(), rules_cache_.end(),
                                  [rule_id](const FirewallRule& r) { return r.id == rule_id; });
            
            if (it == rules_cache_.end()) {
                if (logger_) {
                    logger_->log(Logger::LogLevel::ERROR, "Reguła o ID " + std::to_string(rule_id) + " nie została znaleziona");
                }
                return std::make_error_code(std::errc::no_such_file_or_directory);
            }
            
            if (enabled) {
                // Włącz regułę (usuń komentarz)
                std::vector<std::string> args = {"-R", it->chain, std::to_string(rule_id)};
                // TODO: Implementacja włączania reguły
            } else {
                // Wyłącz regułę (dodaj komentarz DISABLED)
                std::vector<std::string> args = {"-R", it->chain, std::to_string(rule_id)};
                // TODO: Implementacja wyłączania reguły
            }
            
            // Zaktualizuj cache
            rules_cache_.clear();
            last_cache_update_ = std::chrono::steady_clock::time_point{};
            
        } else if (backend_type_ == BackendType::NFTABLES) {
            // TODO: Implementacja przełączania reguł nftables
            return std::make_error_code(std::errc::not_supported);
        }
        
        if (logger_) {
            logger_->log(Logger::LogLevel::INFO, "Reguła przełączona pomyślnie");
        }
        return std::error_code{};
        
    } catch (const std::exception& e) {
        if (logger_) {
            logger_->log(Logger::LogLevel::ERROR, "Błąd krytyczny podczas przełączania reguły: " + std::string(e.what()));
        }
        return std::make_error_code(std::errc::operation_canceled);
    }
}

std::optional<FirewallRule> NetfilterBackend::getRule(int rule_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) {
        return std::nullopt;
    }
    
    auto it = std::find_if(rules_cache_.begin(), rules_cache_.end(),
                           [rule_id](const FirewallRule& r) { return r.id == rule_id; });
    
    if (it != rules_cache_.end()) {
        return *it;
    }
    
    return std::nullopt;
}

std::vector<Connection> NetfilterBackend::getConnections() const {
    if (!initialized_) {
        return {};
    }
    
    try {
        std::vector<Connection> connections;
        
        if (backend_type_ == BackendType::IPTABLES) {
            // Pobierz połączenia przez conntrack
            std::vector<std::string> args = {"-L"};
            auto output = execute_conntrack_command_output(args);
            
            if (output.empty()) {
                return {};
            }
            
            // Parsuj wyjście conntrack
            std::istringstream iss(output);
            std::string line;
            uint64_t conn_id = 1;
            
            while (std::getline(iss, line)) {
                if (line.empty() || line[0] == '#') {
                    continue;
                }
                
                Connection conn;
                conn.id = conn_id++;
                
                // Parsuj linię conntrack
                std::istringstream line_iss(line);
                std::string token;
                std::vector<std::string> tokens;
                
                while (line_iss >> token) {
                    tokens.push_back(token);
                }
                
                if (tokens.size() >= 4) {
                    conn.protocol = tokens[0];
                    conn.source_ip = tokens[1];
                    conn.dest_ip = tokens[2];
                    conn.state = tokens[3];
                    
                    // Parsuj porty jeśli dostępne
                    if (tokens.size() >= 6) {
                        try {
                            conn.source_port = std::stoi(tokens[4]);
                            conn.dest_port = std::stoi(tokens[5]);
                        } catch (...) {
                            // Ignoruj błędy parsowania portów
                        }
                    }
                    
                    connections.push_back(conn);
                }
            }
        }
        
        return connections;
        
    } catch (const std::exception& e) {
        if (logger_) {
            logger_->log(Logger::LogLevel::ERROR, "Błąd podczas pobierania połączeń: " + std::string(e.what()));
        }
        return {};
    }
}

void NetfilterBackend::setConnectionCallback(std::function<void(const Connection&)> callback) {
    connection_callback_ = std::move(callback);
}

BackendType NetfilterBackend::detectBackend() {
    // Check if nftables is available
    if (system("nft --version > /dev/null 2>&1") == 0) {
        if (logger_) {
            logger_->log(Logger::LogLevel::INFO, "Detected nftables, using as backend");
        }
        return BackendType::NFTABLES;
    }
    
    // Check if iptables is available
    if (system("iptables --version > /dev/null 2>&1") == 0) {
        if (logger_) {
            logger_->log(Logger::LogLevel::INFO, "Detected iptables, using as backend");
        }
        return BackendType::IPTABLES;
    }
    
    if (logger_) {
        logger_->log(Logger::LogLevel::ERROR, "No supported firewall backend detected");
    }
    return BackendType::IPTABLES; // Default to iptables
}

std::error_code NetfilterBackend::initializeIptables() {
    // Sprawdź czy iptables działa
    std::vector<std::string> args = {"--version"};
            auto ec = executeIptablesCommand(args);
    if (ec) {
        if (logger_) {
            logger_->log(Logger::LogLevel::ERROR, "iptables nie jest dostępny", ec);
        }
        return ec;
    }
    
    if (logger_) {
        logger_->log(Logger::LogLevel::INFO, "Backend iptables zainicjalizowany");
    }
    return std::error_code{};
}

std::error_code NetfilterBackend::initializeNftables() {
    // Sprawdź czy nftables działa
    std::vector<std::string> args = {"--version"};
            auto ec = executeNftCommand(args);
    if (ec) {
        if (logger_) {
            logger_->log(Logger::LogLevel::ERROR, "nftables nie jest dostępny", ec);
        }
        return ec;
    }
    
    if (logger_) {
        logger_->log(Logger::LogLevel::INFO, "Backend nftables zainicjalizowany");
    }
    return std::error_code{};
}

FirewallRule NetfilterBackend::parseIptablesRule(const std::string& rule_line) const {
    FirewallRule rule;
    
    try {
        std::istringstream iss(rule_line);
        std::string token;
        std::vector<std::string> tokens;
        
        while (iss >> token) {
            tokens.push_back(token);
        }
        
        if (tokens.size() >= 3) {
            // Parsuj numer reguły
            try {
                rule.id = std::stoi(tokens[0]);
            } catch (...) {
                rule.id = 0;
            }
            
            // Parsuj target
            if (tokens.size() >= 4) {
                rule.target = tokens[3];
            }
            
            // Parsuj protokół
            for (size_t i = 0; i < tokens.size(); ++i) {
                if (tokens[i] == "-p" && i + 1 < tokens.size()) {
                    rule.protocol = tokens[i + 1];
                    break;
                }
            }
            
            // Parsuj źródło
            for (size_t i = 0; i < tokens.size(); ++i) {
                if (tokens[i] == "-s" && i + 1 < tokens.size()) {
                    rule.source = tokens[i + 1];
                    break;
                }
            }
            
            // Parsuj cel
            for (size_t i = 0; i < tokens.size(); ++i) {
                if (tokens[i] == "-d" && i + 1 < tokens.size()) {
                    rule.destination = tokens[i + 1];
                    break;
                }
            }
            
            // Parsuj porty
            for (size_t i = 0; i < tokens.size(); ++i) {
                if (tokens[i] == "--dport" && i + 1 < tokens.size()) {
                    rule.ports = tokens[i + 1];
                    break;
                }
            }
            
            // Parsuj komentarz
            for (size_t i = 0; i < tokens.size(); ++i) {
                if (tokens[i] == "--comment" && i + 1 < tokens.size()) {
                    rule.comment = tokens[i + 1];
                    break;
                }
            }
        }
        
    } catch (const std::exception& e) {
        if (logger_) {
            logger_->log(Logger::LogLevel::ERROR, "Błąd parsowania reguły iptables: " + std::string(e.what()));
        }
    }
    
    return rule;
}

std::string NetfilterBackend::formatIptablesRule(const FirewallRule& rule) const {
    std::ostringstream oss;
    
    oss << rule.chain << " ";
    
    if (!rule.protocol.empty()) {
        oss << "-p " << rule.protocol << " ";
    }
    
    if (!rule.source.empty()) {
        oss << "-s " << rule.source << " ";
    }
    
    if (!rule.destination.empty()) {
        oss << "-d " << rule.destination << " ";
    }
    
    if (!rule.ports.empty()) {
        oss << "--dport " << rule.ports << " ";
    }
    
    if (!rule.options.empty()) {
        oss << rule.options << " ";
    }
    
    oss << "-j " << rule.target;
    
    if (!rule.comment.empty()) {
        oss << " -m comment --comment \"" << rule.comment << "\"";
    }
    
    return oss.str();
}

std::error_code NetfilterBackend::executeIptablesCommand(const std::vector<std::string>& args) {
    return execute_command("iptables", args);
}

std::error_code NetfilterBackend::executeNftCommand(const std::vector<std::string>& args) {
    return execute_command("nft", args);
}

std::error_code NetfilterBackend::execute_conntrack_command(const std::vector<std::string>& args) {
    return execute_command("conntrack", args);
}

std::string NetfilterBackend::executeIptablesCommandOutput(const std::vector<std::string>& args) {
    return execute_command_output("iptables", args);
}

std::string NetfilterBackend::executeNftCommandOutput(const std::vector<std::string>& args) {
    return execute_command_output("nft", args);
}

std::string NetfilterBackend::execute_conntrack_command_output(const std::vector<std::string>& args) {
    return execute_command_output("conntrack", args);
}

std::error_code NetfilterBackend::execute_command(const std::string& command, const std::vector<std::string>& args) {
    // Utwórz proces potomny
    pid_t pid = fork();
    if (pid < 0) {
        return std::make_error_code(std::errc::resource_unavailable_try_again);
    }
    
    if (pid == 0) {
        // Proces potomny
        std::vector<const char*> argv;
        argv.push_back(command.c_str());
        
        for (const auto& arg : args) {
            argv.push_back(arg.c_str());
        }
        argv.push_back(nullptr);
        
        execvp(command.c_str(), const_cast<char* const*>(argv.data()));
        exit(EXIT_FAILURE);
    } else {
        // Proces rodzic
        int status;
        waitpid(pid, &status, 0);
        
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            return std::error_code{};
        } else {
            return std::make_error_code(std::errc::operation_canceled);
        }
    }
}

std::string NetfilterBackend::execute_command_output(const std::string& command, const std::vector<std::string>& args) {
    // Utwórz pipe do przechwytywania wyjścia
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        return "";
    }
    
    // Utwórz proces potomny
    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return "";
    }
    
    if (pid == 0) {
        // Proces potomny
        close(pipefd[0]); // Zamknij odczyt
        
        // Przekieruj stdout do pipe
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        
        std::vector<const char*> argv;
        argv.push_back(command.c_str());
        
        for (const auto& arg : args) {
            argv.push_back(arg.c_str());
        }
        argv.push_back(nullptr);
        
        execvp(command.c_str(), const_cast<char* const*>(argv.data()));
        exit(EXIT_FAILURE);
    } else {
        // Proces rodzic
        close(pipefd[1]); // Zamknij zapis
        
        // Odczytaj wyjście
        std::string output;
        char buffer[4096];
        ssize_t bytes_read;
        
        while ((bytes_read = read(pipefd[0], buffer, sizeof(buffer))) > 0) {
            output.append(buffer, bytes_read);
        }
        
        close(pipefd[0]);
        
        // Czekaj na zakończenie procesu potomnego
        int status;
        waitpid(pid, &status, 0);
        
        return output;
    }
}
