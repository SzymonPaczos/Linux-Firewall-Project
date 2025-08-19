#include <iostream>
#include <memory>
#include <csignal>
#include <system_error>
#include <filesystem>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <fstream>
#include <chrono>
#include <thread>
#include "DaemonCore.h"

/**
 * App is the main application class that manages the firewall daemon lifecycle and process management.
 * It handles daemonization, signal processing, PID file management, and coordinates the overall application flow.
 * The class ensures proper initialization, runs the daemon core, and manages graceful shutdown procedures.
 * It acts as the entry point and process manager for the entire firewall daemon system.
 */
class App {
public:
    /**
     * Constructs a new App instance and prepares it for daemon operation.
     * Initializes internal state and prepares signal handling infrastructure.
     */
    App();
    
    /**
     * Destructor that ensures proper cleanup of application resources.
     * Automatically removes PID files and cleans up any remaining resources.
     */
    ~App();
    
    /**
     * Runs the main daemon loop and manages the application lifecycle.
     * Initializes the daemon core, runs the main loop, and handles shutdown.
     * @param argc Number of command line arguments
     * @param argv Array of command line arguments
     * @return Exit code indicating success or failure
     */
    int run(int argc, char* argv[]);
    
    /**
     * Stops the daemon gracefully by stopping the daemon core.
     * This method is called when receiving shutdown signals.
     */
    void stop();

private:
    /**
     * Checks if the current process has root privileges required for firewall operations.
     * Verifies effective user ID to ensure proper permissions for netfilter access.
     * @return true if running as root, false otherwise
     */
    bool checkRootPrivileges() const;
    
    /**
     * Checks if another instance of the firewall daemon is already running.
     * Examines PID file existence and process status to prevent multiple daemon instances.
     * @return true if daemon is already active, false otherwise
     */
    bool checkDaemonRunning() const;
    
    /**
     * Writes the current process ID to the PID file for process management.
     * Creates the PID directory if needed and stores the daemon's process identifier.
     * @return true if PID file was written successfully, false otherwise
     */
    bool writePidFile() const;
    
    /**
     * Removes the PID file when the daemon shuts down.
     * Cleans up the process identifier file to prevent stale PID references.
     */
    void removePidFile() const;
    
    /**
     * Runs the main daemon loop that keeps the application alive.
     * Monitors the daemon core status and waits for shutdown signals.
     */
    void runDaemonLoop();

private:
    std::unique_ptr<DaemonCore> daemon_core_;
};

App::App() = default;

App::~App() {
    removePidFile();
}

int App::run(int argc, char* argv[]) {
    try {
        // Initialize daemon core
        daemon_core_ = std::make_unique<DaemonCore>();
        
        // Set signal handler
        daemon_core_->setSignalHandler([this](int sig) {
            if (sig == SIGTERM || sig == SIGINT) {
                stop();
            }
        });
        
        // Start the daemon
        auto ec = daemon_core_->start();
        if (ec) {
            std::cerr << "Error starting daemon: " << ec.message() << std::endl;
            return EXIT_FAILURE;
        }
        
        // Run the main daemon loop
        runDaemonLoop();
        
        return EXIT_SUCCESS;
        
    } catch (const std::exception& e) {
        std::cerr << "Error in daemon: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}

void App::stop() {
    if (daemon_core_) {
        daemon_core_->stop();
    }
}

bool App::checkRootPrivileges() const {
    return geteuid() == 0;
}

bool App::checkDaemonRunning() const {
    const std::string pid_file = "/var/run/firewall-daemon.pid";
    
    if (!std::filesystem::exists(pid_file)) {
        return false;
    }
    
    try {
        std::ifstream pid_stream(pid_file);
        if (pid_stream.is_open()) {
            int pid;
            pid_stream >> pid;
            pid_stream.close();
            
            // Check if process with this PID exists
            if (kill(pid, 0) == 0) {
                return true;
            }
        }
    } catch (...) {
        // Ignore parsing errors
    }
    
    // Remove invalid PID file
    std::filesystem::remove(pid_file);
    return false;
}

bool App::writePidFile() const {
    const std::string pid_file = "/var/run/firewall-daemon.pid";
    const std::string pid_dir = "/var/run";
    
    try {
        // Create directory if it doesn't exist
        if (!std::filesystem::exists(pid_dir)) {
            std::filesystem::create_directories(pid_dir);
        }
        
        std::ofstream pid_stream(pid_file);
        if (pid_stream.is_open()) {
            pid_stream << getpid() << std::endl;
            pid_stream.close();
            return true;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error writing PID file: " << e.what() << std::endl;
    }
    
    return false;
}

void App::removePidFile() const {
    const std::string pid_file = "/var/run/firewall-daemon.pid";
    try {
        std::filesystem::remove(pid_file);
    } catch (...) {
        // Ignore removal errors
    }
}

void App::runDaemonLoop() {
    // Main daemon loop
    while (daemon_core_->isRunning()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

/**
 * Main function - creates and runs the application
 * @param argc Argument count
 * @param argv Argument vector
 * @return Exit code
 */
int main(int argc, char* argv[]) {
    try {
        // Check root privileges
        if (!App::checkRootPrivileges()) {
            std::cerr << "Error: This program must be run as root" << std::endl;
            return EXIT_FAILURE;
        }
        
        // Check if daemon is already running
        if (App::checkDaemonRunning()) {
            std::cerr << "Error: Firewall daemon is already running" << std::endl;
            return EXIT_FAILURE;
        }
        
        // Create and run application
        App app;
        
        // Set up signal handling for graceful shutdown
        signal(SIGTERM, [&app](int sig) {
            std::cout << "Received SIGTERM, shutting down gracefully..." << std::endl;
            app.stop();
        });
        
        signal(SIGINT, [&app](int sig) {
            std::cout << "Received SIGINT, shutting down gracefully..." << std::endl;
            app.stop();
        });
        
        // Write PID file
        if (!app.writePidFile()) {
            std::cerr << "Warning: Failed to write PID file" << std::endl;
        }
        
        // Run the daemon
        auto result = app.run(argc, argv);
        
        // Clean up PID file
        app.removePidFile();
        
        return result;
        
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
}
