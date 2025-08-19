# Makefile for Firewall Daemon
# Uses CMake for building

.PHONY: all build clean install uninstall test help

# Default settings
BUILD_TYPE ?= Release
BUILD_DIR = build
INSTALL_PREFIX ?= /usr/local

# Colors for output
GREEN = \033[0;32m
YELLOW = \033[1;33m
RED = \033[0;31m
NC = \033[0m # No Color

# Default target
all: build

# Create build directory and compile
build: $(BUILD_DIR)
	@echo "$(GREEN)Compiling Firewall Daemon...$(NC)"
	cd $(BUILD_DIR) && cmake .. -DCMAKE_BUILD_TYPE=$(BUILD_TYPE) -DCMAKE_INSTALL_PREFIX=$(INSTALL_PREFIX)
	cd $(BUILD_DIR) && make -j$(shell nproc)
	@echo "$(GREEN)Compilation completed successfully!$(NC)"

# Create build directory
$(BUILD_DIR):
	@echo "$(YELLOW)Creating build directory...$(NC)"
	mkdir -p $(BUILD_DIR)

# Debug build
debug: BUILD_TYPE = Debug
debug: build

# Release build
release: BUILD_TYPE = Release
release: build

# Installation
install: build
	@echo "$(GREEN)Installing Firewall Daemon...$(NC)"
	cd $(BUILD_DIR) && sudo make install
	@echo "$(GREEN)Installation completed successfully!$(NC)"
	@echo "$(YELLOW)Run: sudo systemctl enable firewall-daemon$(NC)"
	@echo "$(YELLOW)Run: sudo systemctl start firewall-daemon$(NC)"

# Uninstallation
uninstall:
	@echo "$(YELLOW)Uninstalling Firewall Daemon...$(NC)"
	cd $(BUILD_DIR) && sudo make uninstall
	@echo "$(GREEN)Uninstallation completed successfully!$(NC)"

# Cleaning
clean:
	@echo "$(YELLOW)Cleaning build files...$(NC)"
	rm -rf $(BUILD_DIR)
	@echo "$(GREEN)Cleaning completed!$(NC)"

# Deep cleaning
distclean: clean
	@echo "$(YELLOW)Removing all generated files...$(NC)"
	find . -name "*.o" -delete
	find . -name "*.so" -delete
	find . -name "*.a" -delete
	find . -name "*.log" -delete
	find . -name "*.pid" -delete
	@echo "$(GREEN)Deep cleaning completed!$(NC)"

# Tests
test: build
	@echo "$(GREEN)Running tests...$(NC)"
	cd $(BUILD_DIR) && make test
	@echo "$(GREEN)Tests completed!$(NC)"

# Check dependencies
check-deps:
	@echo "$(YELLOW)Checking system dependencies...$(NC)"
	@command -v cmake >/dev/null 2>&1 || { echo "$(RED)Error: cmake is not installed$(NC)"; exit 1; }
	@command -v g++ >/dev/null 2>&1 || { echo "$(RED)Error: g++ is not installed$(NC)"; exit 1; }
	@command -v pkg-config >/dev/null 2>&1 || { echo "$(RED)Error: pkg-config is not installed$(NC)"; exit 1; }
	@echo "$(GREEN)All dependencies are available!$(NC)"

# Check library dependencies
check-libs:
	@echo "$(YELLOW)Checking library dependencies...$(NC)"
	@pkg-config --exists libnl-3.0 || { echo "$(RED)Error: libnl3 is not installed$(NC)"; exit 1; }
	@pkg-config --exists libnftnl || { echo "$(RED)Error: libnftnl is not installed$(NC)"; exit 1; }
	@pkg-config --exists dbus-1 || { echo "$(RED)Error: dbus-1 is not installed$(NC)"; exit 1; }
	@echo "$(GREEN)All libraries are available!$(NC)"

# Install dependencies (Ubuntu/Debian)
install-deps-ubuntu:
	@echo "$(YELLOW)Installing dependencies for Ubuntu/Debian...$(NC)"
	sudo apt update
	sudo apt install -y build-essential cmake pkg-config
	sudo apt install -y libnl-3-dev libnftnl-dev libdbus-1-dev nlohmann-json3-dev libsystemd-dev
	@echo "$(GREEN)Dependencies installed!$(NC)"

# Install dependencies (CentOS/RHEL/Fedora)
install-deps-fedora:
	@echo "$(YELLOW)Installing dependencies for CentOS/RHEL/Fedora...$(NC)"
	sudo dnf install -y gcc-c++ cmake pkg-config
	sudo dnf install -y libnl3-devel libnftnl-devel dbus-devel nlohmann-json-devel systemd-devel
	@echo "$(GREEN)Dependencies installed!$(NC)"

# Install dependencies (Arch Linux)
install-deps-arch:
	@echo "$(YELLOW)Installing dependencies for Arch Linux...$(NC)"
	sudo pacman -S --noconfirm base-devel cmake pkg-config
	sudo pacman -S --noconfirm libnl libnftnl dbus nlohmann-json
	@echo "$(GREEN)Dependencies installed!$(NC)"

# Check service status
status:
	@echo "$(YELLOW)Checking Firewall Daemon service status...$(NC)"
	@systemctl is-active firewall-daemon >/dev/null 2>&1 && echo "$(GREEN)Service is active$(NC)" || echo "$(RED)Service is not active$(NC)"
	@systemctl is-enabled firewall-daemon >/dev/null 2>&1 && echo "$(GREEN)Service is enabled$(NC)" || echo "$(RED)Service is not enabled$(NC)"

# Start service
start:
	@echo "$(YELLOW)Starting Firewall Daemon service...$(NC)"
	sudo systemctl start firewall-daemon
	@echo "$(GREEN)Service started!$(NC)"

# Stop service
stop:
	@echo "$(YELLOW)Stopping Firewall Daemon service...$(NC)"
	sudo systemctl stop firewall-daemon
	@echo "$(GREEN)Service stopped!$(NC)"

# Restart service
restart:
	@echo "$(YELLOW)Restarting Firewall Daemon service...$(NC)"
	sudo systemctl restart firewall-daemon
	@echo "$(GREEN)Service restarted!$(NC)"

# Enable service
enable:
	@echo "$(YELLOW)Enabling Firewall Daemon service...$(NC)"
	sudo systemctl enable firewall-daemon
	@echo "$(GREEN)Service enabled!$(NC)"

# Disable service
disable:
	@echo "$(YELLOW)Disabling Firewall Daemon service...$(NC)"
	sudo systemctl disable firewall-daemon
	@echo "$(GREEN)Service disabled!$(NC)"

# Show logs
logs:
	@echo "$(YELLOW)Showing recent service logs...$(NC)"
	sudo journalctl -u firewall-daemon -n 50 --no-pager

# Show logs in real-time
logs-follow:
	@echo "$(YELLOW)Showing logs in real-time...$(NC)"
	sudo journalctl -u firewall-daemon -f

# Check configuration
config-check:
	@echo "$(YELLOW)Checking configuration...$(NC)"
	@if [ -f /etc/firewall-daemon/firewall-daemon.conf ]; then \
		echo "$(GREEN)Configuration file exists$(NC)"; \
		echo "$(YELLOW)Contents:$(NC)"; \
		cat /etc/firewall-daemon/firewall-daemon.conf; \
	else \
		echo "$(RED)Configuration file does not exist$(NC)"; \
	fi

# Help
help:
	@echo "$(GREEN)Firewall Daemon - Makefile$(NC)"
	@echo ""
	@echo "$(YELLOW)Targets:$(NC)"
	@echo "  build          - Compile project (default)"
	@echo "  debug          - Compile in debug mode"
	@echo "  release        - Compile in release mode"
	@echo "  install        - Install daemon"
	@echo "  uninstall      - Uninstall daemon"
	@echo "  clean          - Clean build files"
	@echo "  distclean      - Deep cleaning"
	@echo "  test           - Run tests"
	@echo ""
	@echo "$(YELLOW)Dependency checking:$(NC)"
	@echo "  check-deps     - Check system dependencies"
	@echo "  check-libs     - Check library dependencies"
	@echo ""
	@echo "$(YELLOW)Dependency installation:$(NC)"
	@echo "  install-deps-ubuntu  - Ubuntu/Debian"
	@echo "  install-deps-fedora  - CentOS/RHEL/Fedora"
	@echo "  install-deps-arch    - Arch Linux"
	@echo ""
	@echo "$(YELLOW)Service management:$(NC)"
	@echo "  status         - Check service status"
	@echo "  start          - Start service"
	@echo "  stop           - Stop service"
	@echo "  restart        - Restart service"
	@echo "  enable         - Enable service"
	@echo "  disable        - Disable service"
	@echo ""
	@echo "$(YELLOW)Logs and configuration:$(NC)"
	@echo "  logs           - Show recent logs"
	@echo "  logs-follow    - Show logs in real-time"
	@echo "  config-check   - Check configuration"
	@echo ""
	@echo "$(YELLOW)Examples:$(NC)"
	@echo "  make install-deps-ubuntu  # Install dependencies on Ubuntu"
	@echo "  make build                # Compile project"
	@echo "  make install              # Install daemon"
	@echo "  make enable               # Enable service"
	@echo "  make start                # Start service"
	@echo "  make logs                 # Show logs"

# Project information
info:
	@echo "$(GREEN)Firewall Daemon - Project Information$(NC)"
	@echo ""
	@echo "$(YELLOW)Version:$(NC) 1.0.0"
	@echo "$(YELLOW)Author:$(NC) Firewall Daemon Team"
	@echo "$(YELLOW)License:$(NC) MIT"
	@echo "$(YELLOW)Language:$(NC) C++20"
	@echo "$(YELLOW)Platform:$(NC) Linux"
	@echo ""
	@echo "$(YELLOW)Features:$(NC)"
	@echo "  - Firewall management (iptables/nftables)"
	@echo "  - Connection monitoring (conntrack)"
	@echo "  - DBus API"
	@echo "  - JSON logging"
	@echo "  - Least privilege model"
	@echo "  - Sandboxing (seccomp/AppArmor)"
	@echo ""
	@echo "$(YELLOW)Requirements:$(NC)"
	@echo "  - Linux kernel 4.18+"
	@echo "  - GCC 10+ or Clang 12+"
	@echo "  - CMake 3.16+"
	@echo "  - libnl3, libnftnl, dbus-1, nlohmann-json"