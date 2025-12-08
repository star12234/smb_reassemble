#include "smb_reassemble.h"
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

char *output_dir = NULL;

static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    if (h->caplen < 14) return;
    size_t offset = 14;
    uint16_t eth_type = (bytes[12] << 8) | bytes[13];
    
    if (eth_type == 0x8100 && h->caplen >= 18) {
        offset += 4;
        eth_type = (bytes[offset - 2] << 8) | bytes[offset - 1];
    }
    if (eth_type != 0x0800) return;
    
    const struct ip *ip = (const struct ip *)(bytes + offset);
    if (ip->ip_p != IPPROTO_TCP) return;
    
    uint32_t ip_hdr_len = ip->ip_hl * 4;
    const struct tcphdr *tcp = (const struct tcphdr *)((const uint8_t *)ip + ip_hdr_len);
    
    size_t ip_len = ntohs(ip->ip_len);
    size_t tcp_hdr_len = tcp->th_off * 4;
    if (ip_len < ip_hdr_len + tcp_hdr_len) return;
    
    size_t payload_len = ip_len - ip_hdr_len - tcp_hdr_len;
    const uint8_t *payload = (const uint8_t *)tcp + tcp_hdr_len;
    
    uint16_t src_port = ntohs(tcp->th_sport);
    uint16_t dst_port = ntohs(tcp->th_dport);
    
    if (src_port != 445 && src_port != 139 && dst_port != 445 && dst_port != 139) return;
    
    conn_key_t key;
    int dir;
    
    if ((src_port == 445 || src_port == 139)) {
        key.cli_ip = ip->ip_dst.s_addr; key.cli_port = dst_port;
        key.srv_ip = ip->ip_src.s_addr; key.srv_port = src_port;
        dir = 1;
    } else {
        key.cli_ip = ip->ip_src.s_addr; key.cli_port = src_port;
        key.srv_ip = ip->ip_dst.s_addr; key.srv_port = dst_port;
        dir = 0;
    }
    
    connection_t *conn = get_connection(&key);
    feed_tcp_payload(conn, dir, ntohl(tcp->th_seq), payload, payload_len);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: sudo %s <interface> <output_dir>\n", argv[0]);
        return EXIT_FAILURE;
    }
    const char *dev = argv[1];
    output_dir = argv[2];
    
    if (mkdir(output_dir, 0755) != 0 && access(output_dir, F_OK) != 0) {
        perror("mkdir"); return EXIT_FAILURE;
    }
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);
    
    if (!handle) {
        fprintf(stderr, "Error opening device %s: %s\n", dev, errbuf);
        return EXIT_FAILURE;
    }
    
    printf("Monitoring on %s... Press Ctrl+C to stop.\n", dev);
    pcap_loop(handle, 0, packet_handler, NULL);
    
    pcap_close(handle);
    close_all_files();
    return EXIT_SUCCESS;
}