#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>

/* DPDK core libraries:
 * - rte_eal.h: Environment Abstraction Layer - initializes DPDK, manages CPU cores, memory
 * - rte_ethdev.h: Ethernet device framework - manages network ports, RX/TX queues
 * - rte_mbuf.h: Packet buffer management - allocates/frees packet buffers
 * - rte_malloc.h: DPDK memory allocation - NUMA-aware memory allocation
 */
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>

/* Protocol header parsing:
 * - rte_ip.h: IPv4 header structures and checksum functions
 * - rte_udp.h: UDP header structures
 * - rte_tcp.h: TCP header structures
 * - rte_icmp.h: ICMP header structures
 */
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_icmp.h>

/* ================ CONFIGURATION CONSTANTS ================ */

/* RX_RING_SIZE: Number of descriptors in the receive ring
 * Each descriptor points to a packet buffer. 1024 is a good balance
 * between memory usage and performance. Too small = packet drops,
 * too large = wasted memory.
 */
#define RX_RING_SIZE 1024

/* TX_RING_SIZE: Number of descriptors in the transmit ring
 * 512 is sufficient for most use cases since we're not generating
 * massive amounts of traffic (just echo replies).
 */
#define TX_RING_SIZE 512

/* NUM_MBUFS: Total number of packet buffers (mbufs) in the pool
 * 8191 = ~8191 * 2176 bytes ≈ 17MB of memory per socket.
 * This should handle even high traffic loads.
 */
#define NUM_MBUFS 8191

/* MBUF_CACHE_SIZE: Per-core cache size for mbufs
 * Each CPU core gets this many mbufs in its local cache to avoid
 * lock contention on the shared pool. 250 is a good default.
 */
#define MBUF_CACHE_SIZE 250

/* BURST_SIZE: Number of packets to process in one batch
 * DPDK works best when processing packets in batches (bursts).
 * 32 packets per burst is optimal for most NICs and CPUs.
 */
#define BURST_SIZE 32

/* ================ GLOBAL STATE ================ */

/* Force quit flag - marked volatile because it's accessed from
 * signal handler and main loop (different contexts). 'volatile'
 * prevents compiler optimizations that might cache the value.
 */
static volatile bool force_quit = false;

/* ================ SIGNAL HANDLING ================ */

/**
 * signal_handler() - Catches Ctrl+C and termination signals
 * @signum: Signal number (SIGINT = 2 from Ctrl+C, SIGTERM = 15 from kill)
 *
 * This function runs in signal context - must be async-signal-safe.
 * That's why we only set a flag and don't do complex operations.
 */
static void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        printf("\nProgram terminating...\n");
        force_quit = true;  /* Signal main loop to exit */
    }
}

/* ================ MAC ADDRESS PRINTING ================ */

/**
 * print_mac() - Print a MAC address in human-readable format
 * @prefix: String to print before the MAC (e.g., "MAC src=")
 * @addr: Pointer to ethernet address structure (6 bytes)
 *
 * MAC addresses are 6 octets (bytes) typically written as hex: xx:xx:xx:xx:xx:xx
 * Example: 08:00:27:5b:f0:0f (VirtualBox default MAC)
 */
static void print_mac(const char *prefix, struct rte_ether_addr *addr) {
    /* addr_bytes[0] is first octet (most significant), addr_bytes[5] is last */
    printf("%s %02x:%02x:%02x:%02x:%02x:%02x",
           prefix,
           addr->addr_bytes[0], addr->addr_bytes[1],
           addr->addr_bytes[2], addr->addr_bytes[3],
           addr->addr_bytes[4], addr->addr_bytes[5]);
}

/* ================ IP ADDRESS PRINTING ================ */

/**
 * print_ip() - Print an IPv4 address in dotted decimal format
 * @prefix: String to print before the IP (e.g., "IP src=")
 * @ip: 32-bit IPv4 address in network byte order (big-endian)
 *
 * IPv4 addresses are 32 bits, stored in network byte order (big-endian).
 * Example: 0xC0A80164 (hex) = 192.168.1.100 (decimal)
 *
 * The shifts extract each octet:
 * - (ip >> 24) & 0xFF: Most significant byte (first octet)
 * - (ip >> 16) & 0xFF: Second octet
 * - (ip >> 8) & 0xFF:  Third octet
 * - ip & 0xFF:         Least significant byte (last octet)
 */
static void print_ip(const char *prefix, uint32_t ip) {
    printf("%s %u.%u.%u.%u",
           prefix,
           (ip >> 24) & 0xFF,       /* First octet */
               (ip >> 16) & 0xFF,   /* Second octet */
               (ip >> 8) & 0xFF,    /* Third octet */
               ip & 0xFF);          /* Fourth octet */
}

/* ================ ECHO REPLY FUNCTION ================ */

/**
 * send_echo_reply() - Send back a copy of the received packet
 * @mbuf: Received packet buffer (will NOT be freed here)
 * @port_id: Network port to send the reply on
 *
 * This function implements the "echo" behavior: it creates a new packet,
 * copies the entire original packet, swaps source/destination MAC and IP,
 * recalculates checksums, and sends it back.
 *
 * This is essentially a L2/L3 reflector/forwarder.
 */
static void send_echo_reply(struct rte_mbuf *mbuf, uint16_t port_id) {
    struct rte_ether_hdr *eth_hdr;      /* Original Ethernet header */
    struct rte_mbuf *reply;              /* New mbuf for the reply */
    struct rte_ether_hdr *reply_eth;     /* Reply Ethernet header */
    uint16_t pkt_len;                     /* Packet length in bytes */

    /* STEP 1: Allocate a new mbuf for the reply
     * mbuf->pool points to the memory pool this mbuf came from.
     * We allocate from the same pool to keep memory on same NUMA node.
     *
     * rte_pktmbuf_alloc() gets a free mbuf from the pool.
     * Returns NULL if pool is exhausted (out of memory).
     */
    reply = rte_pktmbuf_alloc(mbuf->pool);
    if (!reply) {
        printf("Could not allocate memory for reply\n");
        return;
    }

    /* STEP 2: Get pointers to headers and packet length
     * rte_pktmbuf_mtod() converts mbuf pointer to data pointer
     * We cast to appropriate header structure types.
     */
    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    pkt_len = mbuf->pkt_len;  /* Total packet length including all headers */

    /* STEP 3: Copy entire packet data
     * We copy byte-for-byte the original packet into the new mbuf.
     * This preserves all headers, options, and payload.
     */
    char *src_data = rte_pktmbuf_mtod(mbuf, char *);
    char *dst_data = rte_pktmbuf_mtod(reply, char *);
    rte_memcpy(dst_data, src_data, pkt_len);  /* Fast memory copy (optimized) */

    /* STEP 4: Swap MAC addresses
     * For echo reply, the packet must go back to the original sender.
     * So original destination becomes new source, original source becomes new destination.
     */
    reply_eth = rte_pktmbuf_mtod(reply, struct rte_ether_hdr *);
    struct rte_ether_addr tmp_mac;

    /* Save original source MAC, then swap */
    rte_ether_addr_copy(&reply_eth->src_addr, &tmp_mac);
    rte_ether_addr_copy(&reply_eth->dst_addr, &reply_eth->src_addr);
    rte_ether_addr_copy(&tmp_mac, &reply_eth->dst_addr);

    /* STEP 5: If IPv4 packet, swap IP addresses and fix checksums
     * rte_be_to_cpu_16 converts 16-bit value from network byte order (big-endian)
     * to CPU byte order (little-endian on x86). RTE_ETHER_TYPE_IPV4 = 0x0800
     */
    if (rte_be_to_cpu_16(reply_eth->ether_type) == RTE_ETHER_TYPE_IPV4) {
        struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(reply_eth + 1);
        uint32_t tmp_ip = ip_hdr->src_addr;

        /* Swap IP addresses */
        ip_hdr->src_addr = ip_hdr->dst_addr;
        ip_hdr->dst_addr = tmp_ip;

        /* STEP 5a: Recalculate IPv4 header checksum
         * IPv4 checksum covers only the IP header (not payload).
         * Must be recalculated after modifying IP addresses.
         */
        ip_hdr->hdr_checksum = 0;  /* Zero before calculation */
        ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);  /* Calculate new checksum */

        /* STEP 5b: Handle transport layer protocols (TCP/UDP/ICMP)
         * For TCP/UDP/ICMP, we need to recalculate their checksums
         * because they include a pseudo-header with IP addresses.
         */

        /* TCP protocol handling */
        if (ip_hdr->next_proto_id == IPPROTO_TCP) {
            struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip_hdr + 1);
            tcp->cksum = 0;  /* Zero checksum */
            /* rte_ipv4_udptcp_cksum() calculates TCP checksum including pseudo-header */
            tcp->cksum = rte_ipv4_udptcp_cksum(ip_hdr, tcp);
        }
        /* UDP protocol handling */
        else if (ip_hdr->next_proto_id == IPPROTO_UDP) {
            struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip_hdr + 1);
            udp->dgram_cksum = 0;
            udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip_hdr, udp);
        }
        /* ICMP protocol handling */
        else if (ip_hdr->next_proto_id == IPPROTO_ICMP) {
            struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(ip_hdr + 1);
            /* If this was an ICMP Echo Request (type 8), convert to Echo Reply (type 0) */
            if (icmp->icmp_type == 8) {  /* Echo Request */
                icmp->icmp_type = 0;      /* Echo Reply */
            }
            icmp->icmp_cksum = 0;
            icmp->icmp_cksum = rte_ipv4_udptcp_cksum(ip_hdr, icmp);
        }
    }

    /* STEP 6: Set packet length in the mbuf
     * pkt_len = total length, data_len = length of first segment.
     * For non-segmented packets (our case), both are equal.
     */
    reply->pkt_len = reply->data_len = pkt_len;

    /* STEP 7: Transmit the packet
     * rte_eth_tx_burst() sends a burst of packets (1 packet here).
     * Returns number of packets successfully sent (should be 1).
     * If not 1, transmission failed - we must free the mbuf.
     */
    if (rte_eth_tx_burst(port_id, 0, &reply, 1) != 1) {
        rte_pktmbuf_free(reply);  /* Free unused mbuf */
        printf("Error sending reply\n");
    } else {
        printf("Reply sent successfully\n");
    }
}

/* ================ PACKET PARSING AND LOGGING ================ */

/**
 * parse_and_log_packet() - Parse packet headers and print detailed info
 * @mbuf: Received packet buffer
 * @port_id: Port where packet was received
 *
 * This function dissects the packet layer by layer:
 * 1. Ethernet header (L2)
 * 2. IPv4 header (L3)
 * 3. Transport protocol (L4): TCP/UDP/ICMP
 *
 * After parsing, it triggers the echo reply.
 */
static void parse_and_log_packet(struct rte_mbuf *mbuf, uint16_t port_id) {
    struct rte_ether_hdr *eth_hdr;
    uint16_t ether_type;
    char packet_info[256] = {0};  /* Unused in this version */

    /* Get Ethernet header - first bytes of packet */
    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

    /* Convert ethertype from network to host byte order
     * Common ethertypes:
     * - 0x0800: IPv4
     * - 0x86DD: IPv6
     * - 0x0806: ARP
     */
    ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

    /* ========== L2: ETHERNET LAYER ========== */
    printf("\n[PORT %u] Received a packet %u bytes\n", port_id, mbuf->pkt_len);

    /* Print MAC addresses */
    print_mac("MAC: src=", &eth_hdr->src_addr);
    print_mac("MAC: dst=", &eth_hdr->dst_addr);
    printf("\n");

    /* ========== L3: NETWORK LAYER ========== */
    /* Determine network layer protocol based on ethertype */
    switch (ether_type) {
    case RTE_ETHER_TYPE_IPV4: {  /* 0x0800 - IPv4 */
        /* IPv4 header follows Ethernet header */
        struct rte_ipv4_hdr *ipv4 = (struct rte_ipv4_hdr *)(eth_hdr + 1);

        /* Print IPv4 header fields
         * version_ihl: Upper 4 bits = version (4), lower 4 bits = header length (in 32-bit words)
         * total_length: Entire packet length (header + data)
         * packet_id: Identification field for fragmentation
         * time_to_live: Hop limit
         * next_proto_id: Transport protocol (6=TCP, 17=UDP, 1=ICMP)
         */
        printf("  IPv4: ver=%u ihl=%u tos=%u len=%u id=%u ttl=%u proto=%u\n",
               (ipv4->version_ihl >> 4) & 0x0F,  /* Version = 4 */
                   ipv4->version_ihl & 0x0F,         /* IHL in 32-bit words */
               ipv4->type_of_service,
               rte_be_to_cpu_16(ipv4->total_length),
               rte_be_to_cpu_16(ipv4->packet_id),
               ipv4->time_to_live,
               ipv4->next_proto_id);

        /* Print source and destination IP addresses */
        print_ip("IP src=", ipv4->src_addr);
        print_ip("IP dst=", ipv4->dst_addr);
        printf("\n");

        /* ========== L4: TRANSPORT LAYER ========== */
        /* Calculate start of L4 header:
         * IPv4 header length = ihl * 4 bytes (since ihl is in 32-bit words)
         */
        uint8_t *l4_hdr = (uint8_t *)ipv4 + ((ipv4->version_ihl & 0x0F) * 4);

        /* Parse based on protocol number */
        switch (ipv4->next_proto_id) {
        case IPPROTO_ICMP: {  /* 1 - ICMP */
            struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)l4_hdr;
            printf("ICMP: type=%u code=%u id=%u seq=%u\n",
                   icmp->icmp_type,
                   icmp->icmp_code,
                   rte_be_to_cpu_16(icmp->icmp_ident),
                   rte_be_to_cpu_16(icmp->icmp_seq_nb));

            /* Decode common ICMP types:
             * type 8 = Echo Request (ping request)
             * type 0 = Echo Reply (ping response)
             */
            if (icmp->icmp_type == 8) {
                printf("      → Ping Request\n");
            } else if (icmp->icmp_type == 0) {
                printf("      → Ping Reply\n");
            }
            break;
        }

        case IPPROTO_TCP: {  /* 6 - TCP */
            struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)l4_hdr;
            printf("TCP: src_port=%u dst_port=%u flags=0x%02x seq=%u ack=%u\n",
                   rte_be_to_cpu_16(tcp->src_port),
                   rte_be_to_cpu_16(tcp->dst_port),
                   tcp->tcp_flags,
                   rte_be_to_cpu_32(tcp->sent_seq),
                   rte_be_to_cpu_32(tcp->recv_ack));
            break;
        }

        case IPPROTO_UDP: {  /* 17 - UDP */
            struct rte_udp_hdr *udp = (struct rte_udp_hdr *)l4_hdr;
            printf("UDP: src_port=%u dst_port=%u len=%u\n",
                   rte_be_to_cpu_16(udp->src_port),
                   rte_be_to_cpu_16(udp->dst_port),
                   rte_be_to_cpu_16(udp->dgram_len));
            break;
        }

        default:
            printf("    ❓ L4 protocol: %u\n", ipv4->next_proto_id);
            break;
        }
        break;
    }

    case RTE_ETHER_TYPE_IPV6: {  /* 0x86DD - IPv6 */
        printf("IPv6 packet\n");  /* IPv6 packet */
        break;
    }

    case RTE_ETHER_TYPE_ARP: {  /* 0x0806 - ARP */
        printf("ARP packet\n");  /* ARP packet */
        break;
    }

    default: {  /* Unknown ethertype */
        printf("  Unknown ethernet: 0x%04x\n", ether_type);
        break;
    }
    }

    /* Send echo reply for ALL packets (not just ICMP) */
    printf(" Send echo reply ...\n");
    send_echo_reply(mbuf, port_id);
}

/* ================ PORT INITIALIZATION ================ */

/**
 * init_port() - Configure and start a network port
 * @port_id: Port index to initialize
 * @mbuf_pool: Memory pool for allocating packet buffers
 *
 * This function sets up:
 * - Port configuration (number of RX/TX queues)
 * - RX queue with ring buffer
 * - TX queue with ring buffer
 * - Starts the port and enables promiscuous mode
 *
 * Returns 0 on success, negative on error.
 */
static int init_port(uint16_t port_id, struct rte_mempool *mbuf_pool) {
    struct rte_eth_conf port_conf = {
        .rxmode = { .mtu = 9000 },    /* Support jumbo frames up to 9000 bytes */
        .txmode = { .offloads = 0 },  /* No hardware offloads (simpler) */
    };

    int ret;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;

    printf("Initializing port %u...\n", port_id);  /* Initializing port X... */

    /* STEP 1: Configure the device
     * Parameters: port_id, number of RX queues (1), number of TX queues (1), configuration
     * This must be called before queue setup.
     */
    ret = rte_eth_dev_configure(port_id, 1, 1, &port_conf);
    if (ret < 0) {
        printf("Port configuration error %u\n", port_id);  /* Port configuration error */
        return ret;
    }

    /* STEP 2: Setup RX queue
     * Parameters: port_id, queue_id (0), ring_size, socket_id, rx_conf, mbuf_pool
     * socket_id ensures memory is allocated on correct NUMA node
     */
    ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd,
                                 rte_eth_dev_socket_id(port_id),
                                 NULL, mbuf_pool);
    if (ret < 0) {
        printf("RX queue setup error\n");  /* RX queue setup error */
        return ret;
    }

    /* STEP 3: Setup TX queue
     * Similar to RX but without mbuf_pool (TX uses separate buffers)
     */
    ret = rte_eth_tx_queue_setup(port_id, 0, nb_txd,
                                 rte_eth_dev_socket_id(port_id),
                                 NULL);
    if (ret < 0) {
        printf("TX queue setup error\n");  /* TX queue setup error */
        return ret;
    }

    /* STEP 4: Start the device
     * After this call, the port can receive and transmit packets
     */
    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        printf("Port start error %u\n", port_id);  /* Port start error */
        return ret;
    }

    /* STEP 5: Enable promiscuous mode
     * This makes the NIC receive all packets on the network, not just those
     * destined to its MAC address. Useful for sniffing/forwarding.
     */
    rte_eth_promiscuous_enable(port_id);

    printf("[+] Port %u is ready\n", port_id);  /* Port X ready */
    return 0;
}

/* ================ MAIN PACKET PROCESSING LOOP ================ */

/**
 * packet_processing_loop() - Main loop that receives and processes packets
 * @port_id: Port to receive from
 *
 * This is the heart of the application. It continuously:
 * 1. Receives bursts of packets from the NIC
 * 2. Parses and logs each packet
 * 3. Frees packet buffers
 *
 * Runs until force_quit is set by signal handler.
 */
static void packet_processing_loop(uint16_t port_id) {
    struct rte_mbuf *bufs[BURST_SIZE];  /* Array to hold burst of packets */
    uint16_t nb_rx;                      /* Number of packets received in burst */
    uint64_t total_packets = 0;          /* Total packets processed */

    printf("\nStarting echo server on port %u...\n", port_id);
    printf("Press Ctrl+C to stop \n");
    printf("========================================\n");

    /* Main loop - runs until Ctrl+C pressed */
    while (!force_quit) {
        /* STEP 1: Receive a burst of packets
         * rte_eth_rx_burst() is non-blocking - returns immediately with
         * up to BURST_SIZE packets. Returns actual number received.
         */
        nb_rx = rte_eth_rx_burst(port_id, 0, bufs, BURST_SIZE);

        /* Skip if no packets received */
        if (unlikely(nb_rx == 0))
            continue;

        /* STEP 2: Process each received packet */
        for (uint16_t i = 0; i < nb_rx; i++) {
            total_packets++;
            parse_and_log_packet(bufs[i], port_id);  /* Parse and echo */
            rte_pktmbuf_free(bufs[i]);                /* Free the packet buffer */
        }
    }

    printf("\nTotal packets processed: %lu\n", total_packets);
}

/* ================ PORT DISCOVERY ================ */

/**
 * list_available_ports() - Display all DPDK-compatible network ports
 *
 * Iterates through all available ports and prints:
 * - Port ID
 * - Driver name
 * - MAC address
 *
 * Helps user identify which port to use.
 */
static void list_available_ports(void) {
    uint16_t port_id;
    struct rte_eth_dev_info dev_info;
    struct rte_ether_addr addr;
    uint16_t nb_ports = rte_eth_dev_count_avail();

    printf("\n=== Available ports ===\n");
    printf("Total ports: %u\n", nb_ports);

    if (nb_ports == 0) {
        printf("No DPDK ports available!\n");
        return;
    }

    /* RTE_ETH_FOREACH_DEV is a macro that iterates over all ports */
    RTE_ETH_FOREACH_DEV(port_id) {
        /* Get device info (driver name, capabilities, etc.) */
        (void)rte_eth_dev_info_get(port_id, &dev_info);
        /* Get MAC address */
        rte_eth_macaddr_get(port_id, &addr);

        printf("\nPort %u:\n", port_id);
        printf("  Driver: %s\n", dev_info.driver_name ? dev_info.driver_name : "unknown");
        printf("  MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               addr.addr_bytes[0], addr.addr_bytes[1],
               addr.addr_bytes[2], addr.addr_bytes[3],
               addr.addr_bytes[4], addr.addr_bytes[5]);
    }
    printf("========================\n");
}

/* ================ MAIN FUNCTION ================ */

/**
 * main() - Program entry point
 * @argc: Number of command line arguments
 * @argv: Array of command line arguments
 *
 * DPDK applications have a special argument handling because
 * rte_eal_init() consumes its own arguments (like -l for cores, -n for memory channels)
 * and returns the number of consumed arguments.
 *
 * Usage: sudo ./dpdk_echo -l 0-1 -n 4
 */
int main(int argc, char **argv) {
    int ret;
    uint16_t port_id;
    uint16_t nb_ports;
    struct rte_mempool *mbuf_pool;

    /* STEP 1: Initialize DPDK Environment Abstraction Layer (EAL)
     * This is the most critical step - it sets up:
     * - CPU core affinity
     * - Hugepage memory
     * - PCI device access
     * - Logging
     *
     * rte_eal_init() consumes EAL arguments (like -l, -n, --socket-mem)
     * and returns number of arguments consumed.
     */
    ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        printf("EAL initialization error\n");
        return 1;
    }

    /* STEP 2: Setup signal handlers for graceful shutdown */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* STEP 3: Check if any ports are available
     * rte_eth_dev_count_avail() returns number of usable ports
     */
    nb_ports = rte_eth_dev_count_avail();
    if (nb_ports == 0) {
        printf("No DPDK ports!\n");
        rte_eal_cleanup();  /* Clean up EAL */
        return 1;
    }

    /* STEP 4: Display available ports to user */
    list_available_ports();

    /* STEP 5: Pick the first available port
     * RTE_ETH_FOREACH_DEV iterates and we break after first
     */
    RTE_ETH_FOREACH_DEV(port_id) {
        break;
    }

    printf("\nSelected port %u\n", port_id);

    /* STEP 6: Create memory pool for packet buffers (mbufs)
     * Parameters:
     * - name: "MBUF_POOL" (for debugging)
     * - n: NUM_MBUFS - number of mbufs
     * - cache_size: MBUF_CACHE_SIZE - per-core cache
     * - priv_size: 0 - no private data
     * - data_room_size: RTE_MBUF_DEFAULT_BUF_SIZE (typically 2176 bytes)
     * - socket_id: rte_socket_id() - current NUMA socket
     */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS,
                                        MBUF_CACHE_SIZE, 0,
                                        RTE_MBUF_DEFAULT_BUF_SIZE,
                                        rte_socket_id());
    if (mbuf_pool == NULL) {
        printf("mbuf pool creation error\n");
        rte_eal_cleanup();
        return 1;
    }

    /* STEP 7: Initialize the network port */
    ret = init_port(port_id, mbuf_pool);
    if (ret < 0) {
        printf("Port initialization error\n");
        rte_eal_cleanup();
        return 1;
    }

    /* STEP 8: Enter main packet processing loop
     * This function will run until Ctrl+C is pressed
     */
    packet_processing_loop(port_id);

    /* STEP 9: Cleanup on exit
     * Stop and close the port
     */
    rte_eth_dev_stop(port_id);
    rte_eth_dev_close(port_id);
    rte_eal_cleanup();

    printf("Program finished\n");
    return 0;
}
