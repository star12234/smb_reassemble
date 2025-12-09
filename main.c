#include "smb_reassemble.h"
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

char *output_dir = NULL; // 전역 변수 정의 (실제 메모리 할당)

/* * packet_handler
 * 역할: pcap 라이브러리가 패킷을 잡을 때마다 호출해주는 콜백 함수
 * 변수 설명:
 * - h: 캡처된 패킷의 메타데이터 (시간, 길이 등)
 * - bytes: 패킷의 실제 바이트 데이터
 */
static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    if (h->caplen < 14) return;
    
    size_t offset = 14; // 이더넷 헤더 길이
    uint16_t eth_type = (bytes[12] << 8) | bytes[13];
    
    // VLAN(802.1Q) 태그가 있으면 건너뜀
    if (eth_type == 0x8100 && h->caplen >= 18)
    {
        offset += 4;
        eth_type = (bytes[offset - 2] << 8) | bytes[offset - 1];
    }
    if (eth_type != 0x0800) return; // IPv4만 처리
    
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
    
    // SMB 포트(445, 139)가 아니면 무시
    if (src_port != 445 && src_port != 139 && dst_port != 445 && dst_port != 139) return;
    
    conn_key_t key;
    int dir; // 0: Client->Server, 1: Server->Client
    
    if ((src_port == 445 || src_port == 139)) {
        // 출발지가 SMB 포트면 서버가 보낸 패킷
        key.cli_ip = ip->ip_dst.s_addr; key.cli_port = dst_port;
        key.srv_ip = ip->ip_src.s_addr; key.srv_port = src_port;
        dir = 1;
    } else {
        // 도착지가 SMB 포트면 클라이언트가 보낸 패킷
        key.cli_ip = ip->ip_src.s_addr; key.cli_port = src_port;
        key.srv_ip = ip->ip_dst.s_addr; key.srv_port = dst_port;
        dir = 0;
    }
    
    connection_t *conn = get_connection(&key);
    // 시퀀스 번호(Host Byte Order)와 함께 처리 위임
    feed_tcp_payload(conn, dir, ntohl(tcp->th_seq), payload, payload_len);
}

int main(int argc, char *argv[]) {
    // 인자 개수 확인
    if (argc != 3) {
        fprintf(stderr, "Usage: sudo %s <interface> <output_dir>\n", argv[0]);
        return EXIT_FAILURE;
    }
    const char *dev = argv[1]; // 감청할 네트워크 인터페이스 이름 (예: eth0)
    output_dir = argv[2];      // 파일 저장 경로
    
    // 출력 디렉토리 생성
    if (mkdir(output_dir, 0755) != 0 && access(output_dir, F_OK) != 0) {
        perror("mkdir"); return EXIT_FAILURE;
    }
    
    char errbuf[PCAP_ERRBUF_SIZE];
    // 실시간 캡처 시작 (Promiscuous Mode)
    pcap_t *handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);
    
    if (!handle) {
        fprintf(stderr, "Error opening device %s: %s\n", dev, errbuf);
        return EXIT_FAILURE;
    }
    
    printf("Monitoring on %s... Press Ctrl+C to stop.\n", dev);
    // 패킷 캡처 루프 시작 (무한 루프)
    pcap_loop(handle, 0, packet_handler, NULL); //인자에 2번째가 0 또는 -1이면 무한 정수가 들어가면 해당 횟수만큼 반복
    
    pcap_close(handle);
    close_all_files();
    return EXIT_SUCCESS;
}
