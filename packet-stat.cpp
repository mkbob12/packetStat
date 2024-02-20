#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#define MAX_IPS 1000

struct IP {
    uint32_t ip;
    int send_packets;
    int receive_packets;
    int send_bytes;
    int receive_bytes;
};

struct IP ip_packet[MAX_IPS];
int ip_count = 0;

void update_stats(uint32_t ip, int send_bytes, int receive_bytes) {
    for (int i = 0; i < ip_count; i++) {
        if (ip_packet[i].ip == ip) {
            // Update existing entry
            ip_packet[i].send_packets++;
            ip_packet[i].receive_packets++;
            ip_packet[i].send_bytes += send_bytes;
            ip_packet[i].receive_bytes += receive_bytes;
            return;
        }
    }

    // 초기 설정 
    ip_packet[ip_count].ip = ip;
    ip_packet[ip_count].send_packets = 1;
    ip_packet[ip_count].receive_packets = 1;
    ip_packet[ip_count].send_bytes = send_bytes;
    ip_packet[ip_count].receive_bytes = receive_bytes;
    ip_count++;
}

void packet_handler(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14);

    if (ip_header->ip_v == 4) {
        uint32_t source_ip = ip_header->ip_src.s_addr;
        uint32_t dest_ip = ip_header->ip_dst.s_addr;

         char source_ip_str[INET_ADDRSTRLEN];
        char dest_ip_str[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &(ip_header->ip_src), source_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip_str, INET_ADDRSTRLEN);

        printf("Source IP: %s\n", source_ip_str);
        printf("Destination IP: %s\n", dest_ip_str);
        printf("Packet Length: %d\n", pkthdr->len); 
        printf("================================\n");

        update_stats(source_ip, pkthdr->len, 0); // 출발지니깐 송신 패킷 길이만 + 
        update_stats(dest_ip, 0, pkthdr->len);   // 목적지니깐 수신 패킷만 길이만 + 
    
    }
}

int main(int argc, char *argv[]) {
    // ... (same as your existing code)
    if (argc != 2) {
        printf("Usage: %s <pcap_file>\n", argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(argv[1], errbuf);

    if (handle == NULL) {
        fprintf(stderr, "파일을 읽을 수 없다.'%s': %s\n", argv[1], errbuf);
        return 2;
    }

    pcap_loop(handle, 0, packet_handler, NULL);

    for (int i = 0; i < ip_count; i++) {
        char source_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_packet[i].ip), source_ip, INET_ADDRSTRLEN);

        printf("IP: %s\n", source_ip);
        printf("송신 패킷 개수: %d\n", ip_packet[i].send_packets);
        printf("수신 패킷 개수: %d\n", ip_packet[i].receive_packets);
        printf("송신 패킷 바이트: %d\n", ip_packet[i].send_bytes);
        printf("수신 패킷 바이트: %d\n", ip_packet[i].receive_bytes);
        printf("=======================================\n");
    }

    pcap_close(handle);

    return 0;
}
