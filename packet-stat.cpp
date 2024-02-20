#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h> 
#include <netinet/udp.h> 
#include <string.h>

#define MAX_IPS 100
#define MAX_CONVERSATIONS 10

struct IP {
    uint32_t ip;
    int send_packets;
    int receive_packets;
    int send_bytes;
    int receive_bytes;
    int port;
};

struct Mac {
    uint8_t source_mac[6];
    uint8_t dest_mac[6];
};
struct Conversation {
    char source_ip[INET_ADDRSTRLEN];
    uint16_t source_port;
    char dest_ip[INET_ADDRSTRLEN];
    uint16_t dest_port;
};

struct IP ip_packet[MAX_IPS];
int ip_count = 0;

struct Conversation conversation_list[MAX_CONVERSATIONS];
int conversation_count = 0;

struct Mac mac_list[MAX_IPS];
int mac_count = 0;


void update_stats(uint32_t ip, uint16_t port, int send_bytes, int receive_bytes) {
    for (int i = 0; i < ip_count; i++) {
        if (ip_packet[i].ip == ip && ip_packet[i].port == port) {
            ip_packet[i].send_packets += (send_bytes > 0) ? 1 : 0;
            ip_packet[i].receive_packets += (receive_bytes > 0) ? 1 : 0;
            ip_packet[i].send_bytes += send_bytes;
            ip_packet[i].receive_bytes += receive_bytes;
            return;
        }
    }

    ip_packet[ip_count].ip = ip;
    ip_packet[ip_count].port = port;
    ip_packet[ip_count].send_packets += (send_bytes > 0) ? 1 : 0;
    ip_packet[ip_count].receive_packets += (receive_bytes > 0) ? 1 : 0;
    ip_packet[ip_count].send_bytes = send_bytes;
    ip_packet[ip_count].receive_bytes = receive_bytes;
    ip_count++;
}


int is_duplicate_mac(const uint8_t* source_mac, const uint8_t* dest_mac) {
    for (int i = 0; i < mac_count; i++) {
        if (memcmp(mac_list[i].source_mac, source_mac, 6) == 0 &&
            memcmp(mac_list[i].dest_mac, dest_mac, 6) == 0) {
            return 1;  // MAC addresses already exist
        }
    }
    return 0;  // MAC addresses not found
}

void add_mac(const uint8_t* source_mac, const uint8_t* dest_mac) {
    memcpy(mac_list[mac_count].source_mac, source_mac, 6);
    memcpy(mac_list[mac_count].dest_mac, dest_mac, 6);
    mac_count++;
}

void print_mac(const uint8_t* source_mac, const uint8_t* dest_mac) {
    if (!is_duplicate_mac(source_mac, dest_mac)) {
    
        add_mac(source_mac, dest_mac);
    }
}
void print_ip(char* source_ip_str, char* dest_ip_str, int packet_len) {
    printf("Source IP: %s\n", source_ip_str);
    printf("Destination IP: %s\n", dest_ip_str);
    printf("IP Packet Length: %d\n", packet_len);
    printf("================================\n");
}


int is_duplicate_conversation(const char* source_ip, uint16_t source_port, const char* dest_ip, uint16_t dest_port) {
    for (int i = 0; i < conversation_count; i++) {
        if (strcmp(conversation_list[i].source_ip, source_ip) == 0 &&
            conversation_list[i].source_port == source_port &&
            strcmp(conversation_list[i].dest_ip, dest_ip) == 0 &&
            conversation_list[i].dest_port == dest_port) {
            return 1;  // Conversation already exists
        }
    }
    return 0;  // Conversation not found
}

void add_conversation(const char* source_ip, uint16_t source_port, const char* dest_ip, uint16_t dest_port) {
    strcpy(conversation_list[conversation_count].source_ip, source_ip);
    conversation_list[conversation_count].source_port = source_port;
    strcpy(conversation_list[conversation_count].dest_ip, dest_ip);
    conversation_list[conversation_count].dest_port = dest_port;
    conversation_count++;
}

void print_conversation(char* source_ip, uint16_t source_port, char* dest_ip, uint16_t dest_port) {
    if (!is_duplicate_conversation(source_ip, source_port, dest_ip, dest_port)) {
        printf("Conversation: %s:%d <-> %s:%d\n", source_ip, source_port, dest_ip, dest_port);
        printf("=======================================\n");
        add_conversation(source_ip, source_port, dest_ip, dest_port);
    }
}
void packet_handler(u_char *, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct ether_header *ether_header = (struct ether_header *)packet;
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
    struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));

    if (ip_header->ip_v == 4) {
        uint32_t source_ip = ip_header->ip_src.s_addr;
        uint32_t dest_ip = ip_header->ip_dst.s_addr;

        char source_ip_str[INET_ADDRSTRLEN];
        char dest_ip_str[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &(ip_header->ip_src), source_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip_str, INET_ADDRSTRLEN);

        print_mac(ether_header->ether_shost, ether_header->ether_dhost);
        print_conversation(source_ip_str, ntohs(tcp_header->th_sport), dest_ip_str, ntohs(tcp_header->th_dport));
        update_stats(source_ip, ntohs(tcp_header->th_sport), pkthdr->len, 0);
        update_stats(dest_ip, ntohs(tcp_header->th_dport), 0, pkthdr->len);


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

    for (int i = 0; i < ip_count; i++) {
        char source_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_packet[i].ip), source_ip, INET_ADDRSTRLEN);

        printf("IP Address %s Port %d \n", source_ip, ip_packet[i].port);
        printf("송신 패킷 개수: %d\n", ip_packet[i].send_packets);
        printf("수신 패킷 개수: %d\n", ip_packet[i].receive_packets);
        printf("송신 패킷 바이트: %d\n", ip_packet[i].send_bytes);
        printf("수신 패킷 바이트: %d\n", ip_packet[i].receive_bytes);
        printf("=======================================\n");
    }

    for(int j = 0; j< mac_count; j++){
         printf("Ethernet Source MAC:");
        for (int i = 0; i < 6; i++) {
            if (i == 5) {
                printf("%02x\n", mac_list[j].source_mac[i]);
                break;
            }
            printf("%02x:", mac_list[j].source_mac[i]);
        }
        printf("Ethernet Destination MAC: ");
        for (int i = 0; i < 6; i++) {
            if (i == 5) {
                printf("%02x\n", mac_list[j].dest_mac[i]);
                break;
            }
            printf("%02x:", mac_list[j].dest_mac[i]);
        }
    }

    pcap_close(handle);

    return 0;
}
