#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

void packet_handler(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Assuming Ethernet headers are present

    // Check if it's an IPv4 packet
    if (ip_header->ip_v == 4) {
        char source_ip[INET_ADDRSTRLEN];
        char dest_ip[INET_ADDRSTRLEN];

        // Convert IP addresses to strings
        inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

        // Print information
        printf("IP 시작 주소: %s\n", source_ip);
        printf("IP 도착 주소: %s\n", dest_ip);
        printf("Packet 길이: %d\n", pkthdr->len);
        printf("=======================================\n");
    }
}


int main(int argc, char *argv[]) {
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

    
    pcap_close(handle);

    return 0;
}