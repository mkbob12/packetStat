# packetStat
Report Packet Stat
pcap file로부터 packet을 읽어서 IP별 송신 패킷 갯수, 수신 패킷 갯수, 송신 패킷 바이트, 수신 패킷 바이트를 출력

# 실행 방법
g++ packet-stat.cpp -o packet-stat -lpcap

syntax : packet-stat <pcap file>
sample : packet-stat test.pcap
