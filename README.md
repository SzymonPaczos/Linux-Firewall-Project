# Firewall Daemon - Modern Linux Firewall Management Daemon

A modern and secure Linux daemon for firewall management written in C++20. The daemon operates as a system service (systemd service) and supports both iptables and nftables through netlink.

## Features

- **Firewall Management**: Support for iptables and nftables with automatic detection
- **Connection Monitoring**: Real-time network connection monitoring through conntrack
- **DBus API**: Programming interface for firewall management
- **JSON Logging**: Structured logging to syslog in JSON format
- **Security**: Least privilege model with sandboxing (seccomp/AppArmor)
- **Performance**: Asynchronous architecture with caching
- **Systemd Integration**: Full compatibility with systemd as Type=simple service

## System Requirements

- Linux kernel 4.18+ (for modern netfilter features)
- GCC 10+ or Clang 12+ with C++20 support
- CMake 3.16+
- libnl3-dev
- libnftnl-dev
- libdbus-1-dev
- nlohmann-json3-dev
- libsystemd-dev (optional, for better systemd integration)

## Dependency Installation

### Ubuntu/Debian
```bash
sudo apt update
sudo apt install build-essential cmake pkg-config
sudo apt install libnl-3-dev libnftnl-dev libdbus-1-dev nlohmann-json3-dev libsystemd-dev
```

### CentOS/RHEL/Fedora
```bash
sudo dnf install gcc-c++ cmake pkg-config
sudo dnf install libnl3-devel libnftnl-devel dbus-devel nlohmann-json-devel systemd-devel
```

### Arch Linux
```bash
sudo pacman -S base-devel cmake pkg-config
sudo pacman -S libnl libnftnl dbus nlohmann-json systemd-libs
```

## Compilation

1. **Clone the repository**
```bash
git clone https://github.com/your-username/firewall-daemon.git
cd firewall-daemon
```

2. **Create build directory**
```bash
mkdir build && cd build
```

3. **Configure CMake**
```bash
cmake .. -DCMAKE_BUILD_TYPE=Release
```

4. **Compile the project**
```bash
make -j$(nproc)
```

5. **Install**
```bash
sudo make install
```

## Running

### As systemd service (recommended)
```bash
# Enable and start the service
sudo systemctl enable firewall-daemon
sudo systemctl start firewall-daemon

# Check status
sudo systemctl status firewall-daemon

# View logs
sudo journalctl -u firewall-daemon -f

# Reload configuration
sudo systemctl reload firewall-daemon

# Stop the service
sudo systemctl stop firewall-daemon
```

### Manual execution
```bash
# Run as background daemon (systemd will manage the process)
sudo ./firewall-daemon

# Check status
sudo systemctl status firewall-daemon

# View real-time logs
sudo journalctl -u firewall-daemon -f
```

## Configuration

The main configuration file is located at `/etc/firewall-daemon/firewall-daemon.conf`. You can customize:

- Logging level
- Firewall backend type (iptables/nftables)
- Conntrack monitoring parameters
- DBus settings
- Security options
- Performance limits

## DBus API

The daemon exposes the following methods through DBus:

### Methods
- `ListRules()` - returns list of active rules
- `AddRule(rule: string)` - adds a rule
- `DeleteRule(id: int)` - removes a rule
- `GetConnections()` - returns active connections

### Signals
- `ConnectionEvent` - emitted on new connection

### Python Usage Example
```python
import dbus

# Connect to system bus
bus = dbus.SystemBus()
service = bus.get_object('org.firewall.Daemon', '/org/firewall/Daemon')
interface = dbus.Interface(service, 'org.firewall.Daemon')

# Get list of rules
rules = interface.ListRules()
print(f"Found {len(rules)} rules")

# Add a rule
rule = "INPUT:ACCEPT:tcp:any:any:80"
result = interface.AddRule(rule)
print(f"Rule added: {result}")

# Get connections
connections = interface.GetConnections()
print(f"Active connections: {len(connections)}")
```

### D-Bus CLI Usage Example
```bash
# Get list of rules
dbus-send --system --dest=org.firewall.Daemon \
    /org/firewall/Daemon org.firewall.Daemon.ListRules

# Add a rule
dbus-send --system --dest=org.firewall.Daemon \
    /org/firewall/Daemon org.firewall.Daemon.AddRule \
    string:"INPUT:ACCEPT:tcp:any:any:80"
```

## Rule Format

The daemon supports two rule formats:

### Simple format
```
chain:target:protocol:source:destination:ports
```

**Examples:**
```
INPUT:ACCEPT:tcp:any:any:80
OUTPUT:DROP:udp:192.168.1.0/24:any:any
FORWARD:REJECT:any:any:any:any
```

### Iptables format
```
-A INPUT -p tcp --dport 80 -j ACCEPT
-I OUTPUT -s 192.168.1.0/24 -j DROP
```

## Monitoring and Logging

### System logs
```bash
# View real-time logs
sudo journalctl -u firewall-daemon -f

# Filter by level
sudo journalctl -u firewall-daemon -p info

# View logs from specific time
sudo journalctl -u firewall-daemon --since "1 hour ago"
```

### JSON logs
All logs are in JSON format for easy parsing:

```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "level": "INFO",
  "message": "Rule added successfully",
  "ident": "firewall-daemon",
  "action": "added",
  "rule": "INPUT:ACCEPT:tcp:any:any:80"
}
```

### Metrics
The daemon collects performance metrics available through:
- File `/var/log/firewall-daemon/metrics.log`
- Prometheus endpoint (optional)
- DBus interface

## Security

### Least privilege model
- Minimal root privileges
- Seccomp sandboxing
- Optional AppArmor
- Filesystem access restrictions

### Capabilities
- `CAP_NET_ADMIN` - firewall management
- `CAP_NET_RAW` - raw socket access
- `CAP_SYS_ADMIN` - system operations

### Sandboxing
```bash
# Check seccomp profile
sudo cat /proc/$(pgrep firewall-daemon)/status | grep Seccomp

# Check AppArmor (if enabled)
sudo aa-status | grep firewall-daemon
```

## Troubleshooting

### Check service status
```bash
sudo systemctl status firewall-daemon
```

### Check logs
```bash
sudo journalctl -u firewall-daemon -n 100
```

### Check permissions
```bash
# Check if daemon has required capabilities
sudo cat /proc/$(pgrep firewall-daemon)/status | grep Cap

# Check file permissions
ls -la /var/run/firewall-daemon.pid
ls -la /etc/firewall-daemon/
```

### Debugging
```bash
# Run in debug mode
sudo ./firewall-daemon --foreground

# Check DBus connections
dbus-monitor --system | grep firewall
```

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   DaemonCore    │    │  NetfilterBackend│    │  ConntrackMonitor│
│                 │    │                  │    │                 │
│ - Component     │◄──►│ - iptables       │◄──►│ - Netlink       │
│   management    │    │ - nftables       │    │ - Conntrack     │
│ - Main loop     │    │ - Rule cache     │    │ - Events        │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  DbusInterface  │    │   FirewallService│    │     Logger      │
│                 │    │                  │    │                 │
│ - DBus API      │◄──►│ - Rule parsing   │◄──►│ - JSON logs     │
│ - Signals       │    │ - Validation     │    │ - Syslog        │
│ - Callbacks     │    │                  │    │ - Timestamps    │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## Development

### Project structure
```
src/
├── daemon/           # Main daemon code
│   ├── main.cpp      # Entry point
│   ├── DaemonCore.h  # Main class
│   └── Logger.h      # Logging system
├── netfilter/        # Firewall backend
│   ├── NetfilterBackend.h
│   └── ConntrackMonitor.h
└── dbus/             # DBus interface
    ├── DbusInterface.h
    └── FirewallService.h
```

### Adding new features
1. Add header in appropriate directory
2. Implement functionality
3. Add unit tests
4. Update documentation
5. Add logging and error handling

### Testing
```bash
# Run unit tests
make test

# Run integration tests
make integration-test

# Check code coverage
make coverage
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## Support

- **Issues**: [GitHub Issues](https://github.com/your-username/firewall-daemon/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-username/firewall-daemon/discussions)
- **Wiki**: [GitHub Wiki](https://github.com/your-username/firewall-daemon/wiki)

## Roadmap

- [ ] Full nftables support
- [ ] REST API interface
- [ ] Web dashboard
- [ ] Prometheus integration
- [ ] IPv6 support
- [ ] ML-based automatic rules
- [ ] SIEM system integration
- [ ] Container support (Docker/Kubernetes)

## Acknowledgments

- The netfilter team for excellent documentation
- The DBus community for implementation help
- All open source contributors