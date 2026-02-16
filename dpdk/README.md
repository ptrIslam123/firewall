# `dpdk-echo` - DPDK Packet Parser and Echo Responder

A minimalistic DPDK application that receives network packets, parses them layer by layer (Ethernet → IP → TCP/UDP/ICMP), logs detailed information to stdout, and sends an echo response back to the sender.

## Features

- **Full packet parsing** - Ethernet, IPv4, TCP, UDP, ICMP headers
- **Echo responder** - Returns every received packet back to sender (swaps MAC/IP, recalculates checksums)
- **Detailed logging** - Human-readable output with emoji indicators
- **Zero packet loss** - DPDK's zero-copy architecture ensures high performance
- **Promiscuous mode** - Captures all traffic on the network
- **Graceful shutdown** - Handles Ctrl+C cleanly with statistics

### Hardware Requirements
- x86_64 architecture with at least 2 CPU cores
- 1GB+ of RAM (hugepages recommended)
- Network card compatible with DPDK (Intel, Mellanox, etc.)

### Software Requirements
- Ubuntu 20.04+ / Debian 11+ (or any Linux with DPDK support)
- Linux kernel 5.4+
- DPDK 21.11+ (installed via packages or source)

## Installation
```bash
# Install from packet manager
sudo apt update && install -y dpdk dpdk-dev \
    libdpdk-dev dpdk-igb-uio-dkms build-essential \
    meson ninja-build linux-headers-$(uname -r) \
    pkg-config libnuma-dev

# Instalation from source
wget http://fast.dpdk.org/rel/dpdk-23.11.tar.xz
tar -xf dpdk-23.11.tar.xz
cd dpdk-23.11
meson setup build
cd build
ninja
sudo ninja install
sudo ldconfig
```

### 2. Build

```bash
cmake -B build .
cmake --build build/
```

## Configuration

```bash
sudo bash ./dpdk_configurator.sh
```

## Testing

### From VM
```bash
# Run dpdk-demo-firewall
sudo ./firewall
```

### From Another Machine/VM

```bash
# Ping test
ping <Machine/VM iface ip address>
```
