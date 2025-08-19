#include "DaemonCore.h"
#include "Logger.h"
#include "NetfilterBackend.h"
#include "DbusInterface.h"
#include "ConntrackMonitor.h"
#include <iostream>
#include <csignal>
#include <system_error>
#include <chrono>
#include <thread>
#include <signal.h>

#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

DaemonCore::DaemonCore() {
    try {
        // Initialize logger first
        logger_ = std::make_unique<Logger>();
        if (logger_) {
            logger_->log(Logger::LogLevel::INFO, "DaemonCore zainicjalizowany");
        }
    } catch (const std::exception& e) {
        // Logger initialization failed, continue without logging
    }
}

DaemonCore::~DaemonCore() {
    if (logger_) {
        logger_->log(Logger::LogLevel::INFO, "DaemonCore zniszczony");
    }
    
    try {
        if (running_.load()) {
            stop();
        }
    } catch (...) {
        // Ignore errors during destruction
    }
}

std::error_code DaemonCore::start() {
    if (running_.load()) {
        return std::error_code(EBUSY, std::system_category());
    }
    
    auto result = initializeComponents();
    if (result) {
        return result;
    }
    
    running_.store(true);
    setupSignalHandling();
    
    // Report ready status to systemd
    reportReadyToSystemd();
    
    main_thread_ = std::thread(&DaemonCore::runMainLoop, this);
    
    return std::error_code();
}

std::error_code DaemonCore::stop() {
    if (!running_.load()) {
        return std::error_code(EBUSY, std::system_category());
    }
    
    // Report stopping status to systemd
    reportStoppingToSystemd();
    
    shutdown_requested_.store(true);
    running_.store(false);
    
    if (main_thread_.joinable()) {
        main_thread_.join();
    }
    
    auto result = shutdownComponents();
    
    return result;
}

void DaemonCore::setSignalHandler(std::function<void(int)> handler) {
    signal_handler_ = std::move(handler);
}

std::error_code DaemonCore::initializeComponents() {
    try {
        // Initialize netfilter backend
        netfilter_ = std::make_unique<NetfilterBackend>(logger_);
        auto ec = netfilter_->initialize();
        if (ec) {
            return ec;
        }
        
        // Initialize DBus interface
        dbus_ = std::make_unique<DbusInterface>(logger_);
        dbus_->setNetfilterBackend(netfilter_.get());
        dbus_->setConnectionCallback(connection_callback_);
        
        // Initialize conntrack monitor
        conntrack_ = std::make_unique<ConntrackMonitor>(logger_);
        conntrack_->setConnectionCallback(connection_callback_);
        
        // Start DBus in separate thread
        dbus_thread_ = std::thread([this]() {
            auto ec = dbus_->run();
            if (ec && logger_) {
                logger_->log(Logger::LogLevel::ERROR, "DBus error: " + ec.message());
            }
        });
        
        // Start conntrack monitor
        ec = conntrack_->start();
        if (ec) {
            return ec;
        }
        
        return std::error_code();
        
    } catch (const std::exception& e) {
        if (logger_) {
            logger_->log(Logger::LogLevel::ERROR, "Exception during initialization: " + std::string(e.what()));
        }
        return std::make_error_code(std::errc::operation_canceled);
    }
}

void DaemonCore::runMainLoop() {
    while (running_.load() && !shutdown_requested_.load()) {
        try {
            // Check component health
            if (conntrack_ && !conntrack_->isRunning()) {
                // Restart conntrack monitor if it failed
                conntrack_->start();
            }
            
            // Sleep for a short interval
            std::this_thread::sleep_for(std::chrono::seconds(1));
            
        } catch (const std::exception& e) {
            if (logger_) {
                logger_->log(Logger::LogLevel::ERROR, "Error in main loop: " + std::string(e.what()));
            }
            // Continue running unless shutdown is requested
            if (shutdown_requested_.load()) {
                break;
            }
        }
    }
}

void DaemonCore::setupSignalHandling() {
    // Set up signal handlers for graceful shutdown
    signal(SIGTERM, [this](int sig) {
        // SIGTERM from systemd - graceful shutdown
        shutdown_requested_.store(true);
        if (signal_handler_) {
            signal_handler_(sig);
        }
    });
    
    signal(SIGINT, [this](int sig) {
        // SIGINT from terminal - graceful shutdown
        shutdown_requested_.store(true);
        if (signal_handler_) {
            signal_handler_(sig);
        }
    });
    
    signal(SIGUSR1, [this](int sig) {
        // SIGUSR1 for reload configuration
        if (signal_handler_) {
            signal_handler_(sig);
        }
    });
}

void DaemonCore::reportReadyToSystemd() {
#ifdef HAVE_SYSTEMD
    // Report ready status to systemd if running under systemd
    if (sd_booted() > 0) {
        sd_notify(0, "READY=1\n"
                     "STATUS=Firewall daemon is ready and serving requests\n"
                     "MAINPID=" + std::to_string(getpid()));
    }
#else
    // Fallback when systemd is not available
    (void)0; // Suppress unused parameter warning
#endif
}

void DaemonCore::reportStoppingToSystemd() {
#ifdef HAVE_SYSTEMD
    // Report stopping status to systemd if running under systemd
    if (sd_booted() > 0) {
        sd_notify(0, "STATUS=Firewall daemon is shutting down\n"
                     "STOPPING=1");
    }
#else
    // Fallback when systemd is not available
    (void)0; // Suppress unused parameter warning
#endif
}

void DaemonCore::shutdownComponents() {
    try {
        // Stop conntrack monitor
        if (conntrack_) {
            conntrack_->stop();
        }
        
        // Stop DBus interface
        if (dbus_) {
            dbus_->stop();
        }
        
        // Wait for DBus thread to finish
        if (dbus_thread_.joinable()) {
            dbus_thread_.join();
        }
        
        // Clean up components
        conntrack_.reset();
        dbus_.reset();
        netfilter_.reset();
        logger_.reset();
        
    } catch (const std::exception& e) {
        // Log error but continue shutdown
        if (logger_) {
            logger_->log(Logger::LogLevel::ERROR, "Error during shutdown: " + std::string(e.what()));
        }
    }
}
