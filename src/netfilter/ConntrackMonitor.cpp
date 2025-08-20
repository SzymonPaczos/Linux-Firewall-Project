#include "ConntrackMonitor.h"
#include "Logger.h"
#include <iostream>
#include <sstream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#include <linux/netfilter/nf_conntrack_udp.h>
#include <linux/netfilter/nf_conntrack_icmp.h>
#include <arpa/inet.h>
#include <cstring>
#include <sstream>
#include <iomanip>

ConntrackMonitor::ConntrackMonitor(std::shared_ptr<Logger> logger) 
    : logger_(logger), running_(false), netlink_socket_(-1) {
    if (logger_) {
        logger_->log(Logger::LogLevel::INFO, "ConntrackMonitor created");
    }
}

ConntrackMonitor::~ConntrackMonitor() {
    if (logger_) {
        logger_->log(Logger::LogLevel::INFO, "ConntrackMonitor destroyed");
    }
    
    if (running_.load()) {
        stop();
    }
}

std::error_code ConntrackMonitor::start() {
    if (running_.load()) {
        return std::error_code{};
    }
    
    if (logger_) {
        logger_->log(Logger::LogLevel::INFO, "Uruchamianie monitora conntrack...");
    }
    
    try {
        // Inicjalizuj socket netlink
        auto ec = initializeNetlink();
        if (ec) {
            if (logger_) {
                logger_->logError("Netlink initialization error", ec);
            }
            return ec;
        }
        
        // Uruchom wątek monitorowania
        monitor_thread_ = std::thread(&ConntrackMonitor::monitorLoop, this);
        
        running_.store(true);
        stats_.start_time = std::chrono::steady_clock::now();
        
        if (logger_) {
            logger_->log(Logger::LogLevel::INFO, "Conntrack monitor started successfully");
        }
        return std::error_code{};
        
    } catch (const std::exception& e) {
        if (logger_) {
            logger_->logError("Critical error during startup: " + std::string(e.what()));
        }
        return std::make_error_code(std::errc::operation_canceled);
    }
}

std::error_code ConntrackMonitor::stop() {
    if (!running_.load()) {
        return std::error_code{};
    }
    
    if (logger_) {
        logger_->log(Logger::LogLevel::INFO, "Stopping conntrack monitor...");
    }
    
    shutdown_requested_.store(true);
    running_.store(false);
    
    try {
        // Czekaj na zakończenie wątku monitorowania
        if (monitor_thread_.joinable()) {
            monitor_thread_.join();
        }
        
        // Zamknij socket netlink
        if (netlink_socket_ >= 0) {
            close(netlink_socket_);
            netlink_socket_ = -1;
        }
        
        if (logger_) {
            logger_->log(Logger::LogLevel::INFO, "Conntrack monitor stopped successfully");
        }
        return std::error_code{};
        
    } catch (const std::exception& e) {
        if (logger_) {
            logger_->logError("Error during shutdown: " + std::string(e.what()));
        }
        return std::make_error_code(std::errc::operation_canceled);
    }
}

void ConntrackMonitor::setConnectionCallback(std::function<void(const Connection&)> callback) {
    connection_callback_ = std::move(callback);
}

void ConntrackMonitor::setConntrackCallback(std::function<void(const ConntrackEvent&)> callback) {
    conntrack_callback_ = std::move(callback);
}

std::vector<ConntrackEvent> ConntrackMonitor::getRecentEvents(size_t count) const {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    
    if (events_cache_.size() <= count) {
        return events_cache_;
    }
    
    return std::vector<ConntrackEvent>(events_cache_.end() - count, events_cache_.end());
}

ConntrackMonitor::MonitorStats ConntrackMonitor::getStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void ConntrackMonitor::monitorLoop() {
    if (logger_) {
        logger_->log(Logger::LogLevel::INFO, "Conntrack monitoring loop started");
    }
    
    try {
        while (running_.load() && !shutdown_requested_.load()) {
            auto ec = listenForEvents();
            if (ec) {
                logError("Error listening for events", ec);
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }
        }
        
        if (logger_) {
            logger_->log(Logger::LogLevel::INFO, "Conntrack monitoring loop stopped");
        }
        
    } catch (const std::exception& e) {
        if (logger_) {
            logger_->logError("Critical error in monitoring loop: " + std::string(e.what()));
        }
    }
}

std::error_code ConntrackMonitor::initializeNetlink() {
    // Utwórz socket netlink
    netlink_socket_ = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if (netlink_socket_ < 0) {
        return std::make_error_code(std::errc::connection_refused);
    }
    
    // Ustaw opcje socketu
    int opt = 1;
    if (setsockopt(netlink_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(netlink_socket_);
        netlink_socket_ = -1;
        return std::make_error_code(std::errc::invalid_argument);
    }
    
    // Ustaw timeout
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    if (setsockopt(netlink_socket_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        close(netlink_socket_);
        netlink_socket_ = -1;
        return std::make_error_code(std::errc::invalid_argument);
    }
    
    // Ustaw adres lokalny
    struct sockaddr_nl local_addr;
    memset(&local_addr, 0, sizeof(local_addr));
    local_addr.nl_family = AF_NETLINK;
    local_addr.nl_pid = getpid();
    
    if (bind(netlink_socket_, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        close(netlink_socket_);
        netlink_socket_ = -1;
        return std::make_error_code(std::errc::connection_refused);
    }
    
    // Dołącz do grupy conntrack
    netlink_group_ = NFNLGRP_CONNTRACK_NEW | NFNLGRP_CONNTRACK_UPDATE | 
                     NFNLGRP_CONNTRACK_DESTROY | NFNLGRP_CONNTRACK_EXP_NEW;
    
    if (setsockopt(netlink_socket_, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, 
                   &netlink_group_, sizeof(netlink_group_)) < 0) {
        close(netlink_socket_);
        netlink_socket_ = -1;
        return std::make_error_code(std::errc::connection_refused);
    }
    
    if (logger_) {
        logger_->log(Logger::LogLevel::INFO, "Netlink socket initialized successfully");
    }
    return std::error_code{};
}

std::error_code ConntrackMonitor::listenForEvents() {
    if (netlink_socket_ < 0) {
        return std::make_error_code(std::errc::not_connected);
    }
    
    char buffer[8192];
    struct sockaddr_nl from_addr;
    socklen_t from_len = sizeof(from_addr);
    
    // Nasłuchuj wiadomości netlink
    ssize_t bytes_received = recvfrom(netlink_socket_, buffer, sizeof(buffer), 0,
                                      (struct sockaddr*)&from_addr, &from_len);
    
    if (bytes_received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // Timeout - to nie jest błąd
            return std::error_code{};
        }
        return std::make_error_code(std::errc::connection_reset);
    }
    
    if (bytes_received == 0) {
        return std::error_code{};
    }
    
    // Parsuj wiadomość netlink
            auto event = parseNetlinkMessage(buffer, bytes_received);
    if (event.has_value()) {
        // Dodaj do cache
        {
            std::lock_guard<std::mutex> lock(cache_mutex_);
            events_cache_.push_back(event.value());
            
            // Ogranicz rozmiar cache
            if (events_cache_.size() > 1000) {
                events_cache_.erase(events_cache_.begin());
            }
        }
        
        // Zaktualizuj statystyki
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.events_received++;
            stats_.last_event_time = std::chrono::steady_clock::now();
            
            if (event->type == ConntrackEventType::NEW) {
                stats_.connections_tracked++;
            }
        }
        
        // Wywołaj callbacki
        if (connection_callback_) {
            connection_callback_(event->connection);
        }
        
        if (conntrack_callback_) {
            conntrack_callback_(event.value());
        }
        
        // Loguj zdarzenie
        nlohmann::json event_data;
        event_data["type"] = static_cast<int>(event->type);
        event_data["connection"] = {
            {"id", event->connection.id},
            {"protocol", event->connection.protocol},
            {"source_ip", event->connection.source_ip},
            {"dest_ip", event->connection.dest_ip},
            {"source_port", event->connection.source_port},
            {"dest_port", event->connection.dest_port},
            {"state", event->connection.state}
        };
        
        if (logger_) {
            logger_->log(Logger::LogLevel::DEBUG, "Conntrack event received", event_data);
        }
    }
    
    return std::error_code{};
}

std::optional<ConntrackEvent> ConntrackMonitor::parseNetlinkMessage(const void* data, size_t len) {
    if (len < sizeof(struct nlmsghdr)) {
        return std::nullopt;
    }
    
    const struct nlmsghdr* nlh = static_cast<const struct nlmsghdr*>(data);
    
    // Sprawdź typ wiadomości
    if (nlh->nlmsg_type != NLMSG_DONE && nlh->nlmsg_type != NLMSG_ERROR) {
        ConntrackEvent event;
        
        // Określ typ zdarzenia na podstawie grupy multicast
        if (nlh->nlmsg_type == NFNL_MSG_BATCH_BEGIN) {
            // Początek batch
            return std::nullopt;
        } else if (nlh->nlmsg_type == NFNL_MSG_BATCH_END) {
            // Koniec batch
            return std::nullopt;
        } else if (nlh->nlmsg_type == NFNL_MSG_CONNTRACK_NEW) {
            event.type = ConntrackEventType::NEW;
        } else if (nlh->nlmsg_type == NFNL_MSG_CONNTRACK_UPDATE) {
            event.type = ConntrackEventType::UPDATE;
        } else if (nlh->nlmsg_type == NFNL_MSG_CONNTRACK_DESTROY) {
            event.type = ConntrackEventType::DESTROY;
        } else if (nlh->nlmsg_type == NFNL_MSG_CONNTRACK_EXP_NEW) {
            event.type = ConntrackEventType::EXPIRED;
        } else {
            // Nieznany typ wiadomości
            return std::nullopt;
        }
        
        // Parsuj atrybuty conntrack
        parseConntrackAttributes(data, len, event.connection);
        
        // Ustaw timestamp
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%SZ");
        event.timestamp = ss.str();
        
        return event;
    }
    
    return std::nullopt;
}

void ConntrackMonitor::parseConntrackAttributes(const void* data, size_t len, Connection& conn) {
    if (len < sizeof(struct nlmsghdr)) {
        return;
    }
    
    const struct nlmsghdr* nlh = static_cast<const struct nlmsghdr*>(data);
    const char* payload = static_cast<const char*>(data) + NLMSG_HDRLEN;
    size_t payload_len = len - NLMSG_HDRLEN;
    
    // Parsuj atrybuty netlink
    size_t offset = 0;
    while (offset < payload_len) {
        if (offset + sizeof(struct nlattr) > payload_len) {
            break;
        }
        
        const struct nlattr* attr = reinterpret_cast<const struct nlattr*>(payload + offset);
        size_t attr_len = NLA_ALIGN(attr->nla_len);
        
        if (offset + attr_len > payload_len) {
            break;
        }
        
        // Parsuj atrybuty conntrack
        switch (attr->nla_type) {
            case CTA_TUPLE_ORIG: {
                // Krotka źródłowa
                parse_tuple_attributes(payload + offset + sizeof(struct nlattr), 
                                     attr_len - sizeof(struct nlattr), conn, true);
                break;
            }
            case CTA_TUPLE_REPLY: {
                // Krotka docelowa
                parse_tuple_attributes(payload + offset + sizeof(struct nlattr), 
                                     attr_len - sizeof(struct nlattr), conn, false);
                break;
            }
            case CTA_STATUS: {
                // Status połączenia
                if (attr_len >= sizeof(struct nlattr) + sizeof(uint32_t)) {
                    uint32_t status = *reinterpret_cast<const uint32_t*>(payload + offset + sizeof(struct nlattr));
                    conn.state = std::to_string(status);
                }
                break;
            }
            case CTA_PROTOINFO: {
                // Informacje o protokole
                parse_protoinfo_attributes(payload + offset + sizeof(struct nlattr), 
                                         attr_len - sizeof(struct nlattr), conn);
                break;
            }
        }
        
        offset += attr_len;
    }
}

void ConntrackMonitor::parse_tuple_attributes(const void* data, size_t len, Connection& conn, bool is_orig) {
    size_t offset = 0;
    while (offset < len) {
        if (offset + sizeof(struct nlattr) > len) {
            break;
        }
        
        const struct nlattr* attr = reinterpret_cast<const struct nlattr*>(static_cast<const char*>(data) + offset);
        size_t attr_len = NLA_ALIGN(attr->nla_len);
        
        if (offset + attr_len > len) {
            break;
        }
        
        switch (attr->nla_type) {
            case CTA_IP_V4_SRC:
            case CTA_IP_V6_SRC: {
                if (is_orig) {
                    conn.source_ip = ipToString(static_cast<const char*>(data) + offset + sizeof(struct nlattr), 
                                                 attr->nla_type == CTA_IP_V4_SRC ? AF_INET : AF_INET6);
                }
                break;
            }
            case CTA_IP_V4_DST:
            case CTA_IP_V6_DST: {
                if (!is_orig) {
                    conn.dest_ip = ipToString(static_cast<const char*>(data) + offset + sizeof(struct nlattr), 
                                               attr->nla_type == CTA_IP_V4_DST ? AF_INET : AF_INET6);
                }
                break;
            }
            case CTA_PROTO_SRC_PORT: {
                if (is_orig && attr_len >= sizeof(struct nlattr) + sizeof(uint16_t)) {
                    uint16_t port = ntohs(*reinterpret_cast<const uint16_t*>(static_cast<const char*>(data) + offset + sizeof(struct nlattr)));
                    conn.source_port = port;
                }
                break;
            }
            case CTA_PROTO_DST_PORT: {
                if (!is_orig && attr_len >= sizeof(struct nlattr) + sizeof(uint16_t)) {
                    uint16_t port = ntohs(*reinterpret_cast<const uint16_t*>(static_cast<const char*>(data) + offset + sizeof(struct nlattr)));
                    conn.dest_port = port;
                }
                break;
            }
            case CTA_PROTO_NUM: {
                if (attr_len >= sizeof(struct nlattr) + sizeof(uint8_t)) {
                    uint8_t proto = *reinterpret_cast<const uint8_t*>(static_cast<const char*>(data) + offset + sizeof(struct nlattr));
                    switch (proto) {
                        case IPPROTO_TCP: conn.protocol = "tcp"; break;
                        case IPPROTO_UDP: conn.protocol = "udp"; break;
                        case IPPROTO_ICMP: conn.protocol = "icmp"; break;
                        default: conn.protocol = "unknown"; break;
                    }
                }
                break;
            }
        }
        
        offset += attr_len;
    }
}

void ConntrackMonitor::parse_protoinfo_attributes(const void* data, size_t len, Connection& conn) {
    // Parsuj dodatkowe informacje o protokole (stan TCP, flagi UDP, etc.)
    // TODO: Implementacja parsowania protoinfo
}

std::string ConntrackMonitor::ipToString(const void* addr, int family) const {
    char ip_str[INET6_ADDRSTRLEN];
    
    if (family == AF_INET) {
        if (inet_ntop(AF_INET, addr, ip_str, INET_ADDRSTRLEN)) {
            return std::string(ip_str);
        }
    } else if (family == AF_INET6) {
        if (inet_ntop(AF_INET6, addr, ip_str, INET6_ADDRSTRLEN)) {
            return std::string(ip_str);
        }
    }
    
    return "unknown";
}

void ConntrackMonitor::logError(const std::string& message, const std::error_code& ec) {
    if (logger_) {
        logger_->logError(message, ec);
    }
    
    // Zaktualizuj statystyki błędów
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_.errors_count++;
}
