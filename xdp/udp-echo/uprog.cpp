/* 
 * AF_XDP Packet Receiver - Minimal Working Example
 * 
 * This program demonstrates how to receive packets from XDP eBPF program
 * via AF_XDP sockets. It creates a userspace packet receiver that:
 * 1. Allocates UMEM (User Memory) for packet buffers
 * 2. Creates an AF_XDP socket bound to a specific interface and queue
 * 3. Registers the socket in XSKMAP for XDP redirection
 * 4. Receives and displays incoming packets
 */

#include <cassert>
#include <string>
#include <string_view>
#include <iostream>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <bpf/bpf.h>          // BPF system calls (bpf_obj_get)
#include <xdp/xsk.h>          // AF_XDP socket API (libxdp)
#include <net/if.h>           // Network interface functions (if_nametoindex)
#include <linux/if_link.h>    // XDP constants (XDP_FLAGS_*, XDP_COPY)

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/in.h>

/* ============= CONFIGURATION SECTION ============= */

// Frame size: 4096 bytes (4KB) - standard page size, must be power of two
// This is the size of each buffer in UMEM where packets will be stored
static constexpr size_t FRAME_SZ = 4096;

// Ring size: 4096 descriptors - number of buffers in each ring queue
// Larger rings = higher throughput but more memory usage
static constexpr size_t RING_SZ  = 4096;

// Функция для обмена MAC-адресов
static __always_inline void swap_mac(struct ethhdr *eth)
{
    uint8_t tmp[ETH_ALEN];
    memcpy(tmp, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, tmp, ETH_ALEN);
}

// Функция для обмена IP-адресов
static __always_inline void swap_ip(struct iphdr *ip)
{
    uint32_t tmp = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp;
}

// Функция для обмена UDP-портов
static __always_inline void swap_udp_ports(struct udphdr *udp)
{
    uint16_t tmp = udp->source;
    udp->source = udp->dest;
    udp->dest = tmp;
}

/* set tcp checksum: given IP header and UDP datagram */
void compute_udp_checksum(struct iphdr *pIph, struct udphdr* udp) {
    unsigned short *ipPayload = (unsigned short*)udp;
    unsigned long sum = 0;
    struct udphdr *udphdrp = (struct udphdr*)(ipPayload);
    unsigned short udpLen = htons(udphdrp->len);
    //printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~udp len=%dn", udpLen);
    //add the pseudo header 
    //printf("add pseudo headern");
    //the source ip
    sum += (pIph->saddr>>16)&0xFFFF;
    sum += (pIph->saddr)&0xFFFF;
    //the dest ip
    sum += (pIph->daddr>>16)&0xFFFF;
    sum += (pIph->daddr)&0xFFFF;
    //protocol and reserved: 17
    sum += htons(IPPROTO_UDP);
    //the length
    sum += udphdrp->len;
 
    //add the IP payload
    //printf("add ip payloadn");
    //initialize checksum to 0
    udphdrp->check = 0;
    while (udpLen > 1) {
        sum += * ipPayload++;
        udpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(udpLen > 0) {
        //printf("+++++++++++++++padding: %dn", udpLen);
        sum += ((*ipPayload)&htons(0xFF00));
    }
      //Fold sum to 16 bits: add carrier to result
    //printf("add carriern");
      while (sum>>16) {
          sum = (sum & 0xffff) + (sum >> 16);
      }
    //printf("one's complementn");
      sum = ~sum;
    //set computation result
    udphdrp->check = ((unsigned short)sum == 0x0000)?0xFFFF:(unsigned short)sum;
}

void ProcessPacket(void* pkt, int len) {
    printf("\n=== НОВЫЙ ПАКЕТ ===\n");
    printf("Длина пакета: %d байт\n", len);
    
    void* data_end = (uint8_t*)pkt + len;
    struct ethhdr *eth = (struct ethhdr *)pkt;
    if ((eth + 1) > (struct ethhdr*)data_end) {
        return;
    }
    
    if (eth->h_proto != htons(ETH_P_IP)) {
        printf("Not ip protocol: %d\n", ntohs(eth->h_proto));
        return;
    }
    
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return;
    }
    
    if (ip->protocol != IPPROTO_UDP) {
        printf("Not udp protocol\n");
        return;
    }
    
    int ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20) {
        return;
    }
    
    if ((uint8_t*)ip + ip_hdr_len > data_end) {
        return;
    }
    
    struct udphdr *udp = (struct udphdr *)((uint8_t*)ip + ip_hdr_len);
    if ((void *)(udp + 1) > data_end) {
        return;
    }
    
    // Проверяем порт назначения 12345
    if (ntohs(udp->dest) != 12345) {
        return;
    }
    
    printf("found udp packet\n");
    
    // Меняем MAC-адреса
    swap_mac(eth);
    
    // Меняем IP-адреса
    swap_ip(ip);
    
    // Меняем UDP-порты
    swap_udp_ports(udp);

    //udp->check = htons(0x7555);

    // Создаем pkt_buff для работы с пакетом
    compute_udp_checksum(ip, udp);

    printf("Swapped packet address\n");
    
    printf("\n=== КОНЕЦ ПАКЕТА ===\n\n");
}

// Process redirected packages from the bpf program
int ProcessRX(
    uint32_t rx_packets, 
    struct xsk_ring_cons& rxq,
    uint32_t& rx_idx,
    struct xsk_ring_prod& fq,
    uint32_t& fq_idx,
    struct xsk_ring_prod& txq,
    struct xsk_socket *xsk,
    void *umem_area
) {
    // Counter for received packets
    int tx_count = 0;

    /* 6.2 Process each received packet */
    for (uint32_t i = 0; i < rx_packets; i++) {
        // Get packet descriptor (address and length)
        uint64_t addr = xsk_ring_cons__rx_desc(&rxq, rx_idx + i)->addr;
        uint32_t len = xsk_ring_cons__rx_desc(&rxq, rx_idx + i)->len;
        
        
        printf("[PACKET] %u bytes | Addr: 0x%lx\n", 
                len, (unsigned long)addr);

        // Получаем указатель на данные в UMEM
        void *pkt = xsk_umem__get_data(umem_area, addr);
        
        // Модифицируем пакет прямо в UMEM
        ProcessPacket(pkt, len);
        
        // === НОВОЕ: отправляем пакет обратно ===
        uint32_t tx_idx = 0;
        if (xsk_ring_prod__reserve(&txq, 1, &tx_idx) == 1) {
            struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&txq, tx_idx);
            tx_desc->addr = addr;
            tx_desc->len = len;
            
            xsk_ring_prod__submit(&txq, 1);
            ++tx_count;
        } else {
            // TX очередь полна - возвращаем буфер в FILL для новых RX
            *xsk_ring_prod__fill_addr(&fq, fq_idx++) = addr;
        }
    }
    
    /* 6.4 Release packets from RX queue
        * - Marks descriptors as processed
        * - Makes room for new packets in RX ring
        */
    xsk_ring_cons__release(&rxq, rx_packets);
    
    /* 6.5 Recycle buffers back to Fill Queue
        * - Get the same buffers we just processed
        * - Add them back to Fill Queue for reuse
        * - This is CRITICAL: kernel needs empty buffers to continue
        */
    uint32_t filled = xsk_ring_prod__reserve(&fq, rx_packets, &fq_idx);
    for (uint32_t i = 0; i < filled; i++) {
        *xsk_ring_prod__fill_addr(&fq, fq_idx + i) = xsk_ring_cons__rx_desc(&rxq, rx_idx + i)->addr;
    }
    xsk_ring_prod__submit(&fq, filled);

    return tx_count;
}

// === ИЗМЕНЕНИЕ: добавляем обработку TX COMPLETIONS ===
void ProcessTX(struct xsk_ring_cons& cq, struct xsk_ring_prod& fq) {
    uint32_t cq_idx = 0;
    uint32_t completed = xsk_ring_cons__peek(&cq, 64, &cq_idx);
    
    if (completed > 0) {
        // Возвращаем отправленные буферы в FILL queue
        uint32_t fill_reserved = xsk_ring_prod__reserve(&fq, completed, &cq_idx);
        for (uint32_t i = 0; i < fill_reserved; i++) {
            uint64_t addr = *xsk_ring_cons__comp_addr(&cq, cq_idx + i);
            *xsk_ring_prod__fill_addr(&fq, cq_idx + i) = addr;
        }
        xsk_ring_prod__submit(&fq, fill_reserved);
        xsk_ring_cons__release(&cq, completed);
    }
}

void Usage(std::string_view programName) {
    std::cerr << "Usage: " << programName << " --iface <interface> --queue-id <queue_id>\n"
              << "\nOptions:\n"
              << "  --iface <name>     Interface name (e.g., eth0, lo, ens3)\n"
              << "  --queue-id <num>   RX queue index (0 to num_queues-1)\n"
              << "\nExamples:\n"
              << "  " << programName << " --iface eth0 --queue-id 0\n"
              << "  " << programName << " --iface lo --queue-id 0\n";
}

/* ============= MAIN FUNCTION ============= */
int main(int argc, char** argv) {
    assert(argc > 0);
    std::string_view program{argv[0]};

    if (argc <=  1) {
        Usage(program);
        return EXIT_SUCCESS;
    }

    // Interface name: "lo" - loopback interface for testing
    // Change to "eth0", "ens3", etc. for physical interfaces
    std::string_view iface;

    // Queue ID: 0 - RX queue index to bind to
    // For physical NICs: 0 to (num_queues-1), for loopback always 0
    int queueId = -1;

    for (auto i = 1; i < argc; ) {
        std::string_view arg{argv[i]};

        if (arg == "--iface" && i + 1 < argc) {
            iface = argv[i + 1];
            i += 2;
        } 
        else if (arg == "--queue" && i + 1 < argc) {
            queueId = std::stoi(argv[i + 1]);
            i += 2;
        } else if (arg == "--help" || arg == "-h") {
            Usage(program);
            return EXIT_SUCCESS;
        } else {
            std::cerr << "Error: Unknown argument: " << arg << "\n";
            Usage(program);
            return EXIT_FAILURE;
        }
    }

    if (iface.empty()) {
        std::cerr << "Error: --iface is required\n";
        Usage(program);
        return EXIT_FAILURE;
    }
    
    if (queueId < 0) {
        std::cerr << "Error: --queue-id is required and must be >= 0\n";
        Usage(program);
        return EXIT_FAILURE;
    }

    // ===== PHASE 1: VARIABLE DECLARATIONS =====
    // All variables declared at the beginning (C++ scope rules with throw)
    
    // UMEM (User Memory) area - pre-allocated buffer pool for packets
    void *umem_area = nullptr;
    
    // libxdp handles for UMEM and socket
    struct xsk_umem *umem = nullptr;      // UMEM object
    struct xsk_socket *xsk = nullptr;     // AF_XDP socket
    
    // Four ring queues required for AF_XDP:
    struct xsk_ring_prod fq;    // FILL queue: user → kernel (give empty buffers)
    struct xsk_ring_cons cq;    // COMPLETION queue: kernel → user (TX completed)
    struct xsk_ring_cons rxq;   // RX queue: kernel → user (incoming packets)
    struct xsk_ring_prod txq;   // TX queue: user → kernel (outgoing packets)
    
    // Misc variables
    int ret = 0;                // Return code from libxdp functions
    int xsks_map_fd = 0;        // File descriptor for XSKMAP BPF map
    uint32_t idx = 0;           // Index in ring buffer
    
    
    printf("=== AF_XDP Packet Receiver ===\n");
    printf("Interface: %s, Queue: %d\n\n", iface.data(), queueId);
    
    // ===== PHASE 2: UMEM ALLOCATION AND SETUP =====
    
    /* 2.1 Allocate UMEM area (page-aligned memory)
     * - aligned_alloc(4096, ...) ensures 4KB alignment (required by most NICs)
     * - Size = FRAME_SZ * RING_SZ (e.g., 4096 * 4096 = 16MB)
     * - This memory will be shared between userspace and kernel
     */
    umem_area = aligned_alloc(4096, FRAME_SZ * RING_SZ);
    if (!umem_area) {
        perror("aligned_alloc failed");
        return 1;
    }
    printf("[1] UMEM allocated: %lu bytes\n", 
           (unsigned long)(FRAME_SZ * RING_SZ));
    
    /* 2.2 Create UMEM object
     * - Registers the memory area with the kernel
     * - Creates Fill and Completion ring buffers
     * - UMEM configuration:
     *   - fill_size: Size of Fill ring (how many buffers we give to kernel)
     *   - comp_size: Size of Completion ring (TX completed buffers)
     *   - frame_size: Size of each buffer (must match FRAME_SZ)
     *   - frame_headroom: Optional space before packet data (0 for simplicity)
     */
    struct xsk_umem_config umem_cfg = {
        .fill_size = RING_SZ,       // Fill ring size
        .comp_size = RING_SZ,       // Completion ring size  
        .frame_size = FRAME_SZ,     // Buffer size
        .frame_headroom = 0,        // No extra headroom
        .flags = 0                  // No special flags
    };
    
    ret = xsk_umem__create(&umem, umem_area, FRAME_SZ * RING_SZ, 
                          &fq, &cq, &umem_cfg);
    if (ret) {
        fprintf(stderr, "xsk_umem__create failed: %d\n", ret);
        throw 1;  // Using throw for cleanup (C++ style)
    }
    printf("[2] UMEM created successfully\n");
    
    // ===== PHASE 3: AF_XDP SOCKET CREATION =====
    
    /* 3.1 Create AF_XDP socket
     * - Binds to specific interface (IFNAME) and RX queue (QUEUE_ID)
     * - Shares UMEM with the kernel
     * - Creates RX and TX ring buffers
     * 
     * Socket configuration:
     * - rx_size/tx_size: Ring sizes for RX/TX (must be power of 2)
     * - libxdp_flags: XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD (we use our own eBPF)
     * - xdp_flags: XDP_FLAGS_SKB_MODE (generic mode, works on all interfaces)
     * - bind_flags: XDP_COPY (CRITICAL for loopback - copies packets to UMEM)
     * 
     * NOTE: For physical NICs with driver support, you might use:
     *   - xdp_flags: XDP_FLAGS_DRV_MODE (for zero-copy)
     *   - bind_flags: 0 (for zero-copy mode)
     */
    struct xsk_socket_config xsk_cfg = {
        .rx_size = RING_SZ,          // RX ring size
        .tx_size = RING_SZ,          // TX ring size
        .libxdp_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD, // Don't load default eBPF
        .xdp_flags = XDP_FLAGS_SKB_MODE,     // Generic/SKB mode (works everywhere)
        .bind_flags = XDP_COPY,              // COPY mode for loopback
    };
    
    ret = xsk_socket__create_shared(&xsk, iface.data(), queueId,
                                    umem, &rxq, &txq, &fq, &cq, &xsk_cfg);
    if (ret) {
        fprintf(stderr, "xsk_socket__create_shared failed: %d\n", ret);
        fprintf(stderr, "Possible reasons:\n");
        fprintf(stderr, "1. Interface %s doesn't support XDP\n", iface.data());
        fprintf(stderr, "2. XDP_COPY flag not set for loopback\n");
        fprintf(stderr, "3. eBPF program not loaded on interface\n");
        throw 1;
    }
    printf("[3] AF_XDP socket created, fd=%d\n", xsk_socket__fd(xsk));
    
    // ===== PHASE 4: REGISTER SOCKET IN XSKMAP (CRITICAL STEP) =====
    
    /* 4.1 Get file descriptor for XSKMAP
     * - XSKMAP is a BPF map of type BPF_MAP_TYPE_XSKMAP
     * - It stores AF_XDP socket FDs keyed by queue index
     * - eBPF program looks up sockets in this map for redirection
     * - Map is pinned at /sys/fs/bpf/xsks_map by our eBPF loader
     */
    xsks_map_fd = bpf_obj_get("/sys/fs/bpf/xsks_map");
    if (xsks_map_fd < 0) {
        perror("bpf_obj_get(/sys/fs/bpf/xsks_map)");
        fprintf(stderr, "Ensure eBPF program is loaded: make load\n");
        throw 1;
    }
    
    /* 4.2 Register socket in XSKMAP
     * - xsk_socket__update_xskmap() is the CORRECT way to add socket to map
     * - Previously used bpf_map_update_elem() may silently fail
     * - This is the MOST COMMON source of problems in AF_XDP setups
     * - After this call, eBPF program can redirect packets to our socket
     */
    ret = xsk_socket__update_xskmap(xsk, xsks_map_fd);
    if (ret) {
        fprintf(stderr, "xsk_socket__update_xskmap failed: %d\n", ret);
        fprintf(stderr, "This is the most frequent cause of AF_XDP issues!\n");
        throw 1;
    }
    printf("[4] Socket registered in xsks_map[%d]\n", queueId);
    
    // ===== PHASE 5: FILL QUEUE INITIALIZATION =====
    
    /* 5.1 Reserve descriptors in Fill Queue
     * - Fill Queue is where we give empty buffers to the kernel
     * - Kernel uses these buffers to store incoming packets
     * - We try to reserve ALL descriptors (RING_SZ) at once
     */
    uint32_t n = xsk_ring_prod__reserve(&fq, RING_SZ, &idx);
    if (n != RING_SZ) {
        fprintf(stderr, "Could only reserve %u of %lu FQ descriptors\n", 
                n, (unsigned long)RING_SZ);
        throw 1;
    }
    
    /* 5.2 Fill with buffer addresses
     * - Each descriptor gets an offset into UMEM area
     * - Address = i * FRAME_SZ (linear mapping)
     * - Kernel will write packets starting at these addresses
     */
    for (uint32_t i = 0; i < n; i++) {
        *xsk_ring_prod__fill_addr(&fq, idx + i) = i * FRAME_SZ;
    }
    
    /* 5.3 Submit descriptors to kernel
     * - Makes buffers available for kernel to use
     * - After this, kernel can receive packets into our UMEM
     */
    xsk_ring_prod__submit(&fq, n);
    printf("[5] Fill Queue filled with %u buffers\n", n);
    printf("\n[READY] Waiting for packets (send ping to %s)...\n", iface.data());
    
    // ===== PHASE 6: MAIN PACKET PROCESSING LOOP =====
    
    while (1) {
        uint32_t rx_idx = 0, fq_idx = 0;
        ProcessTX(cq, fq);
        /* 6.1 Check for received packets
         * - xsk_ring_cons__peek() checks RX queue without removing
         * - Returns number of available packets (up to 64 in this batch)
         * - rx_idx is set to starting index in RX ring
         */
        uint32_t rx_packets = xsk_ring_cons__peek(&rxq, 64, &rx_idx);
        if (rx_packets > 0) {
            int tx = ProcessRX(rx_packets, rxq, rx_idx, fq, fq_idx, txq, xsk, umem_area);

            // Будим TX если есть что отправлять
            if (tx > 0) {
                sendto(xsk_socket__fd(xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
            }
        } else {
            /* 6.6 No packets available - sleep briefly
             * - Avoids busy-waiting consuming 100% CPU
             * - 1ms sleep is reasonable for interactive testing
             * - For high-performance: use poll() or busy-poll with needs_wakeup
             */
            usleep(1000); // Sleep for 1 millisecond
        }
    }
    
    // Note: In production, you would have proper cleanup code here
    // This example uses throw for error handling, so cleanup would be in catch block
    return 0;
}