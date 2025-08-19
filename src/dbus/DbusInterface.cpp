#include "DbusInterface.h"
#include "FirewallService.h"
#include "Logger.h"
#include <dbus/dbus.h>
#include <iostream>

DbusInterface::DbusInterface(std::shared_ptr<Logger> logger) 
    : logger_(logger), running_(false), connection_(nullptr) {
    if (logger_) {
        logger_->log(Logger::LogLevel::INFO, "DbusInterface utworzony");
    }
}

DbusInterface::~DbusInterface() {
    if (logger_) {
        logger_->log(Logger::LogLevel::INFO, "DbusInterface zniszczony");
    }
    
    if (running_.load()) {
        stop();
    }
}

std::error_code DbusInterface::initialize() {
    if (initialized_) {
        return std::error_code{};
    }
    
    if (logger_) {
        logger_->log(Logger::LogLevel::INFO, "Inicjalizacja interfejsu DBus...");
    }
    
    try {
        // Inicjalizuj połączenie DBus
        auto ec = initializeConnection();
        if (ec) {
            if (logger_) {
                logger_->log(Logger::LogLevel::ERROR, "Błąd inicjalizacji połączenia DBus", ec);
            }
            return ec;
        }
        
        // Utwórz usługę zapory
        firewall_service_ = std::make_unique<FirewallService>(logger_);
        
        // Rejestruj obiekt usługi
        ec = registerService();
        if (ec) {
            if (logger_) {
                logger_->log(Logger::LogLevel::ERROR, "Błąd rejestracji usługi DBus", ec);
            }
            return ec;
        }
        
        initialized_ = true;
        if (logger_) {
            logger_->log(Logger::LogLevel::INFO, "Interfejs DBus zainicjalizowany pomyślnie");
        }
        return std::error_code{};
        
    } catch (const std::exception& e) {
        if (logger_) {
            logger_->log(Logger::LogLevel::ERROR, "Błąd krytyczny podczas inicjalizacji: " + std::string(e.what()));
        }
        return std::make_error_code(std::errc::operation_canceled);
    }
}

std::error_code DbusInterface::run() {
    if (!initialized_) {
        return std::make_error_code(std::errc::not_connected);
    }
    
    if (running_) {
        return std::error_code{};
    }
    
    if (logger_) {
        logger_->log(Logger::LogLevel::INFO, "Uruchamianie pętli DBus...");
    }
    
    try {
        running_ = true;
        
        // Uruchom pętlę główną DBus
        dbusLoop();
        
        return std::error_code{};
        
    } catch (const std::exception& e) {
        if (logger_) {
            logger_->log(Logger::LogLevel::ERROR, "Błąd krytyczny podczas uruchamiania: " + std::string(e.what()));
        }
        running_ = false;
        return std::make_error_code(std::errc::operation_canceled);
    }
}

std::error_code DbusInterface::stop() {
    if (!running_) {
        return std::error_code{};
    }
    
    if (logger_) {
        logger_->log(Logger::LogLevel::INFO, "Zatrzymywanie interfejsu DBus...");
    }
    
    try {
        running_ = false;
        
        // Zatrzymaj pętlę DBus
        // TODO: Implementacja zatrzymywania pętli DBus
        
        if (logger_) {
            logger_->log(Logger::LogLevel::INFO, "Interfejs DBus zatrzymany pomyślnie");
        }
        return std::error_code{};
        
    } catch (const std::exception& e) {
        if (logger_) {
            logger_->log(Logger::LogLevel::ERROR, "Błąd podczas zatrzymywania: " + std::string(e.what()));
        }
        return std::make_error_code(std::errc::operation_canceled);
    }
}

void DbusInterface::setNetfilterBackend(NetfilterBackend* backend) {
    if (firewall_service_) {
        firewall_service_->setNetfilterBackend(backend);
    }
}

void DbusInterface::setConnectionCallback(std::function<void(const Connection&)> callback) {
    connection_callback_ = std::move(callback);
}

void DbusInterface::emitConnectionEvent(const Connection& connection) {
    if (!initialized_ || !running_) {
        return;
    }
    
    try {
        // Emituj sygnał DBus
        // TODO: Implementacja emitowania sygnału DBus
        
        // Loguj zdarzenie
        nlohmann::json conn_data;
        conn_data["id"] = connection.id;
        conn_data["protocol"] = connection.protocol;
        conn_data["source_ip"] = connection.source_ip;
        conn_data["dest_ip"] = connection.dest_ip;
        conn_data["source_port"] = connection.source_port;
        conn_data["dest_port"] = connection.dest_port;
        conn_data["state"] = connection.state;
        
        if (logger_) {
            logger_->logConnectionEvent("connection_event_emitted", conn_data);
        }
        
    } catch (const std::exception& e) {
        if (logger_) {
            logger_->log(Logger::LogLevel::ERROR, "Błąd podczas emitowania zdarzenia połączenia: " + std::string(e.what()));
        }
    }
}

std::error_code DbusInterface::initializeConnection() {
    // TODO: Implementacja inicjalizacji połączenia DBus
    // Na razie zwracamy sukces
    
    if (logger_) {
        logger_->log(Logger::LogLevel::INFO, "Połączenie DBus zainicjalizowane (symulacja)");
    }
    return std::error_code{};
}

std::error_code DbusInterface::registerService() {
    // TODO: Implementacja rejestracji usługi DBus
    // Na razie zwracamy sukces
    
    if (logger_) {
        logger_->log(Logger::LogLevel::INFO, "Usługa DBus zarejestrowana (symulacja)");
    }
    return std::error_code{};
}

void DbusInterface::dbusLoop() {
    if (logger_) {
        logger_->log(Logger::LogLevel::INFO, "Pętla główna DBus uruchomiona");
    }
    
    try {
        while (running_) {
            // Obsługuj wiadomości DBus
            handleDbusMessage();
            
            // Krótka przerwa
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        if (logger_) {
            logger_->log(Logger::LogLevel::INFO, "Pętla główna DBus zatrzymana");
        }
        
    } catch (const std::exception& e) {
        if (logger_) {
            logger_->log(Logger::LogLevel::ERROR, "Błąd krytyczny w pętli DBus: " + std::string(e.what()));
        }
    }
}

void DbusInterface::handleDbusMessage() {
    // TODO: Implementacja obsługi wiadomości DBus
    // Na razie to jest puste
    
    // Symulacja obsługi wiadomości
    static int message_count = 0;
    if (++message_count % 1000 == 0) {
        if (logger_) {
            logger_->log(Logger::LogLevel::DEBUG, "Obsłużono " + std::to_string(message_count) + " wiadomości DBus");
        }
    }
}

void DbusInterface::logError(const std::string& message, const std::error_code& ec) {
    if (logger_) {
        logger_->logError(message, ec);
    }
}
