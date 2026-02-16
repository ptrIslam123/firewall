#!/bin/bash

# Minimalistic switcher between kernel and DPDK
# Automatic detection of all parameters

# Exit on error
set -e

# Automatic parameter detection
detect_params() {
    echo "Detecting network parameters..."
    
    # Find the first Ethernet controller
    PCI_ADDR=$(lspci | grep -i ethernet | head -1 | cut -d' ' -f1)
    PCI_ADDR="0000:$PCI_ADDR"
    
    # Get kernel driver
    DRIVER_KERNEL=$(lspci -k -s $PCI_ADDR | grep "Kernel modules" | cut -d: -f2 | xargs)
    
    # Get interface name
    INTERFACE=$(ls /sys/bus/pci/devices/$PCI_ADDR/net/ 2>/dev/null | head -1)
    
    # Get vendor and device ID
    VENDOR_DEV=$(lspci -n -s $PCI_ADDR | awk '{print $3}')
    VENDOR_ID=$(echo $VENDOR_DEV | cut -d: -f1)
    DEVICE_ID=$(echo $VENDOR_DEV | cut -d: -f2)
    
    # Get IP information if interface is active
    if [ -n "$INTERFACE" ] && ip link show $INTERFACE &>/dev/null; then
        IP_ADDR=$(ip -4 addr show $INTERFACE | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
        NETWORK=$(ip route show dev $INTERFACE | grep -v default | head -1 | cut -d' ' -f1)
        GATEWAY=$(ip route show default | grep -oP '(?<=via\s)\d+(\.\d+){3}')
    fi
    
    echo "  PCI: $PCI_ADDR"
    echo "  Interface: $INTERFACE"
    echo "  Kernel driver: $DRIVER_KERNEL"
    echo "  Vendor:Device: $VENDOR_ID:$DEVICE_ID"
    [ -n "$IP_ADDR" ] && echo "  IP: $IP_ADDR"
    [ -n "$GATEWAY" ] && echo "  Gateway: $GATEWAY"
}

# Switch to DPDK
switch_to_dpdk() {
    echo "Switching to DPDK..."
    
    # Stop interface
    if [ -n "$INTERFACE" ]; then
        ip link set dev $INTERFACE down 2>/dev/null || true
    fi
    
    # Unbind current driver
    echo "$PCI_ADDR" > /sys/bus/pci/devices/$PCI_ADDR/driver/unbind 2>/dev/null || true
    
    # Clear override
    echo "" > /sys/bus/pci/devices/$PCI_ADDR/driver_override 2>/dev/null || true
    
    # Bind to vfio-pci
    echo "vfio-pci" > /sys/bus/pci/devices/$PCI_ADDR/driver_override
    echo "$PCI_ADDR" > /sys/bus/pci/drivers/vfio-pci/bind 2>/dev/null || true
    
    # Configure hugepages
    echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages 2>/dev/null || true
    
    echo "Done. Device bound to vfio-pci"
}

# Switch to kernel
switch_to_kernel() {
    echo "Switching to kernel stack..."
    
    # Unbind from vfio
    if [ -d /sys/bus/pci/drivers/vfio-pci ]; then
        echo "$PCI_ADDR" > /sys/bus/pci/drivers/vfio-pci/unbind 2>/dev/null || true
    fi
    
    # Clear override
    echo "" > /sys/bus/pci/devices/$PCI_ADDR/driver_override 2>/dev/null || true
    
    # Bind to kernel driver
    echo "$PCI_ADDR" > /sys/bus/pci/drivers/$DRIVER_KERNEL/bind 2>/dev/null || {
        # If it fails, try through dpdk-devbind
        dpdk-devbind.py --bind=$DRIVER_KERNEL $PCI_ADDR 2>/dev/null || true
    }
    
    # Wait
    sleep 2
    
    # Configure network
    if [ -n "$INTERFACE" ]; then
        ip link set dev $INTERFACE up
        
        # Try DHCP
        if command -v dhclient &>/dev/null; then
            dhclient -r $INTERFACE 2>/dev/null || true
            dhclient $INTERFACE 2>/dev/null || true
        fi
        
        # If static IP exists, configure
        if [ -n "$IP_ADDR" ] && [ -n "$GATEWAY" ]; then
            ip addr add $IP_ADDR/24 dev $INTERFACE 2>/dev/null || true
            ip route add default via $GATEWAY dev $INTERFACE 2>/dev/null || true
        fi
        
        echo "Interface $INTERFACE is up"
    fi
    
    echo "Done. Device bound to $DRIVER_KERNEL"
}

# Show status
show_status() {
    echo "===== NETWORK STATUS ====="
    lspci -k -s $PCI_ADDR | grep -E "Ethernet|Kernel"
    
    if command -v dpdk-devbind.py &>/dev/null; then
        dpdk-devbind.py --status | grep -A 5 "Network devices" | grep -E "$PCI_ADDR|drv=" || true
    fi
    
    if [ -n "$INTERFACE" ] && ip link show $INTERFACE &>/dev/null; then
        ip -4 addr show $INTERFACE | grep inet || echo "Interface $INTERFACE: no IP"
        ip route show | grep default || echo "No default route"
    fi
}

# Check internet
check_internet() {
    if ping -c 2 8.8.8.8 &>/dev/null; then
        echo "Internet is available"
        return 0
    else
        echo "Internet is NOT available"
        return 1
    fi
}

# Main menu
main() {
    # Detect parameters
    detect_params
    
    while true; do
        echo ""
        echo "===== DPDK SWITCHER ====="
        echo "1) Show status"
        echo "2) Switch to DPDK"
        echo "3) Switch to kernel"
        echo "4) Check internet"
        echo "5) Exit"
        echo "========================="
        read -p "Choose action [1-5]: " choice
        
        case $choice in
            1) show_status ;;
            2) switch_to_dpdk ;;
            3) switch_to_kernel ;;
            4) check_internet ;;
            5) exit 0 ;;
            *) echo "Invalid choice" ;;
        esac
    done
}

# Check permissions
if [ "$EUID" -ne 0 ]; then
    echo "Run with sudo"
    exit 1
fi

# Start
main
