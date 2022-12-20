/*내 IP 와 타겟 IP를 적어 
 * MAC 주소 얻기
 */

/*이후 ICMP 프로토콜 코드와 이 코드를 합쳐보려고 노력했는데 그게 잘 이루어지지 않았다.
 * ping을 받는 함수를 따로 만들어서 (pingping) 내가 타겟으로 하는 인터페이스(VM2)와 IP를 한번에 적으면 맥 주소, ping까지 출력되는 것을 구현해보려다 실패했다. 
 *  wireshark에 패킷 확인해보면 각각의 코드는  제대로 출력이 되긴 한다.
 */


#include <sys/socket.h>
#include <sys/ioctl.h>
#include <asm/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <arpa/inet.h>  //htons etc
#include <netinet/ip_icmp.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>





#define PROTO_ARP 0x0806
#define ETH2_HEADER_LEN 14
#define HW_TYPE 1
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define BUF_SIZE 60

// Define the Packet Constants
// ping packet size
#define PING_PKT_S 64

// Automatic port number
#define PORT_NO 0

// Automatic port number
#define PING_SLEEP_RATE 1000000 

// Gives the timeout delay for receiving packets
// in seconds
#define RECV_TIMEOUT 1

// Define the Ping Loop
int pingloop=1;





#define debug(x...) printf(x);printf("\n");
#define info(x...) printf(x);printf("\n");
#define warn(x...) printf(x);printf("\n");
#define err(x...) printf(x);printf("\n");




struct arp_header {
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char hardware_len;
    unsigned char protocol_len;
    unsigned short opcode;
    unsigned char sender_mac[MAC_LENGTH];
    unsigned char sender_ip[IPV4_LENGTH];
    unsigned char target_mac[MAC_LENGTH];
    unsigned char target_ip[IPV4_LENGTH];
};

/*
 * Converts struct sockaddr with an IPv4 address to network byte order uin32_t.
 * Returns 0 on success.
 */
int int_ip4(struct sockaddr *addr, uint32_t *ip)
{
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *i = (struct sockaddr_in *) addr;
        *ip = i->sin_addr.s_addr;
        return 0;
    } else {
        err("Not AF_INET");
        return 1;
    }
}

/*
 * Formats sockaddr containing IPv4 address as human readable string.
 * Returns 0 on success.
 */
int format_ip4(struct sockaddr *addr, char *out)
{
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *i = (struct sockaddr_in *) addr;
        const char *ip = inet_ntoa(i->sin_addr);
        if (!ip) {
            return -2;
        } else {
            strcpy(out, ip);
            return 0;
        }
    } else {
        return -1;
    }
}

/*
 * Writes interface IPv4 address as network byte order to ip.
 * Returns 0 on success.
 */
int get_if_ip4(int fd, const char *ifname, uint32_t *ip) {
    int err = -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    if (strlen(ifname) > (IFNAMSIZ - 1)) {
        err("Too long interface name");
        goto out;
    }

    strcpy(ifr.ifr_name, ifname);
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("SIOCGIFADDR");
        goto out;
    }

    if (int_ip4(&ifr.ifr_addr, ip)) {
        goto out;
    }
    err = 0;
out:
    return err;
}

/*
 * Sends an ARP who-has request to dst_ip
 * on interface ifindex, using source mac src_mac and source ip src_ip.
 */
int send_arp(int fd, int ifindex, const unsigned char *src_mac, uint32_t src_ip, uint32_t dst_ip)
{
    int err = -1;
    unsigned char buffer[BUF_SIZE];
    memset(buffer, 0, sizeof(buffer));

    struct sockaddr_ll socket_address;
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_hatype = htons(ARPHRD_ETHER);
    socket_address.sll_pkttype = (PACKET_BROADCAST);
    socket_address.sll_halen = MAC_LENGTH;
    socket_address.sll_addr[6] = 0x00;
    socket_address.sll_addr[7] = 0x00;

    struct ethhdr *send_req = (struct ethhdr *) buffer;
    struct arp_header *arp_req = (struct arp_header *) (buffer + ETH2_HEADER_LEN);
    int index;
    ssize_t ret, length = 0;

    //Broadcast
    memset(send_req->h_dest, 0xff, MAC_LENGTH);

    //Target MAC zero
    memset(arp_req->target_mac, 0x00, MAC_LENGTH);

    //Set source mac to our MAC address
    memcpy(send_req->h_source, src_mac, MAC_LENGTH);
    memcpy(arp_req->sender_mac, src_mac, MAC_LENGTH);
    memcpy(socket_address.sll_addr, src_mac, MAC_LENGTH);

    /* Setting protocol of the packet */
    send_req->h_proto = htons(ETH_P_ARP);

    /* Creating ARP request */
    arp_req->hardware_type = htons(HW_TYPE);
    arp_req->protocol_type = htons(ETH_P_IP);
    arp_req->hardware_len = MAC_LENGTH;
    arp_req->protocol_len = IPV4_LENGTH;
    arp_req->opcode = htons(ARP_REQUEST);

    debug("Copy IP address to arp_req");
    memcpy(arp_req->sender_ip, &src_ip, sizeof(uint32_t));
    memcpy(arp_req->target_ip, &dst_ip, sizeof(uint32_t));

    ret = sendto(fd, buffer, 42, 0, (struct sockaddr *) &socket_address, sizeof(socket_address));
    if (ret == -1) {
        perror("sendto():");
        goto out;
    }
    err = 0;
out:
    return err;
}

/*
 * Gets interface information by name:
 * IPv4
 * MAC
 * ifindex
 */
int get_if_info(const char *ifname, uint32_t *ip, char *mac, int *ifindex)
{
    debug("get_if_info for %s", ifname);
    int err = -1;
    struct ifreq ifr;
    int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sd <= 0) {
        perror("socket()");
        goto out;
    }
    if (strlen(ifname) > (IFNAMSIZ - 1)) {
        printf("Too long interface name, MAX=%i\n", IFNAMSIZ - 1);
        goto out;
    }

    strcpy(ifr.ifr_name, ifname);

    //Get interface index using name
    if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        goto out;
    }
    *ifindex = ifr.ifr_ifindex;
    printf("interface index is %d\n", *ifindex);

    //Get MAC address of the interface
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        goto out;
    }

    //Copy mac address to output
    memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_LENGTH);

    if (get_if_ip4(sd, ifname, ip)) {
        goto out;
    }
    debug("get_if_info OK");

    err = 0;
out:
    if (sd > 0) {
        debug("Clean up temporary socket");
        close(sd);
    }
    return err;
}

/*
 * Creates a raw socket that listens for ARP traffic on specific ifindex.
 * Writes out the socket's FD.
 * Return 0 on success.
 */
int bind_arp(int ifindex, int *fd)
{
    debug("bind_arp: ifindex=%i", ifindex);
    int ret = -1;

    // Submit request for a raw socket descriptor.
    *fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (*fd < 1) {
        perror("socket()");
        goto out;
    }

    debug("Binding to ifindex %i", ifindex);
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(struct sockaddr_ll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    if (bind(*fd, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0) {
        perror("bind");
        goto out;
    }

    ret = 0;
out:
    if (ret && *fd > 0) {
        debug("Cleanup socket");
        close(*fd);
    }
    return ret;
}

/*
 * Reads a single ARP reply from fd.
 * Return 0 on success.
 */
int read_arp(int fd)
{
    debug("read_arp");
    int ret = -1;
    unsigned char buffer[BUF_SIZE];
    ssize_t length = recvfrom(fd, buffer, BUF_SIZE, 0, NULL, NULL);
    int index;
    if (length == -1) {
        perror("recvfrom()");
        goto out;
    }
    struct ethhdr *rcv_resp = (struct ethhdr *) buffer;
    struct arp_header *arp_resp = (struct arp_header *) (buffer + ETH2_HEADER_LEN);
        if (ntohs(rcv_resp->h_proto) != PROTO_ARP) {
        debug("Not an ARP packet");
        goto out;
    }
    if (ntohs(arp_resp->opcode) != ARP_REPLY) {
        debug("Not an ARP reply");
        goto out;
    }
    debug("received ARP len=%ld", length);
    struct in_addr sender_a;
    memset(&sender_a, 0, sizeof(struct in_addr));
    memcpy(&sender_a.s_addr, arp_resp->sender_ip, sizeof(uint32_t));
    struct sockaddr *addr;
    struct sockaddr src_addr;
    socklen_t src_addr_len = sizeof(addr);
    memset(&addr, 0, src_addr_len);
    ssize_t  recv_len = recvfrom(fd, buffer, BUF_SIZE, 0,(struct sockaddr *)addr,&src_addr_len);
        if(recv_len<0){
                perror("Failed to receive message");
                return 1;
        }
        struct arp_header *arp_hdr = (struct arp_header*)buffer;
        unsigned char *sender_mac = arp_hdr->sender_mac;
	

	debug("MAC LEarning : %02X:%02X:%02X:%02X:%02X:%02X",sender_mac[0],arp_resp->sender_mac[1], arp_resp->sender_mac[2], arp_resp->sender_mac[3], arp_resp->sender_mac[4], arp_resp->sender_mac[5]);

    debug("Sender IP: %s", inet_ntoa(sender_a));

    debug("Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X",
          arp_resp->sender_mac[0],
          arp_resp->sender_mac[1],
          arp_resp->sender_mac[2],
          arp_resp->sender_mac[3],
          arp_resp->sender_mac[4],
          arp_resp->sender_mac[5]);
    ret = 0;

out:
return ret;
}

/*
 *
 * Sample code that sends an ARP who-has request on
 * interface <ifname> to IPv4 address <ip>.
 * Returns 0 on success.
 */
int test_arping(const char *ifname, const char *ip) {
     int ret = -1;
     uint32_t dst = inet_addr(ip);
     if (dst == 0 || dst == 0xffffffff) {
         printf("Invalid source IP\n");
         return 1;
     }
 
     int src;
     int ifindex;
     char mac[MAC_LENGTH];
     if (get_if_info(ifname, &src, mac, &ifindex)) {
         err("get_if_info failed, interface %s not found or no IP set?", ifname);
         goto out;
     }
     int arp_fd;
     if (bind_arp(ifindex, &arp_fd)) {
         err("Failed to bind_arp()");
         goto out;
     }
 
     if (send_arp(arp_fd, ifindex, mac, src, dst)) {
         err("Failed to send_arp");
         goto out;
     }
 
     while(1) {
         int r = read_arp(arp_fd);
         if (r == 0) {
             info("Got reply, break out");
             break;
         }
     }

    ret = 0;
out:
    if (arp_fd) {
        close(arp_fd);
        arp_fd = 0;
    }
    return ret;
}

//ping code
//
//
//



struct ping_pkt
{
        struct icmphdr hdr;
        char msg[PING_PKT_S-sizeof(struct icmphdr)];
};



unsigned short checksum(void *b, int len)
{ unsigned short *buf = b;
        unsigned int sum=0;
        unsigned short result;

        for ( sum = 0; len > 1; len -= 2 )
                sum += *buf++;
        if ( len == 1 )
                sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        result = ~sum;
        return result;
}


// Interrupt handler
void intHandler(int dummy)
{
        pingloop=0;
}


char *dns_lookup(char *addr_host, struct sockaddr_in *addr_con)
{
        printf("\nResolving DNS..\n");
        struct hostent *host_entity;
        char *ip=(char*)malloc(NI_MAXHOST*sizeof(char));
        int i;

        if ((host_entity = gethostbyname(addr_host)) == NULL)
        {
                // No ip found for hostname
                return NULL;
        }

        //filling up address structure
        strcpy(ip, inet_ntoa(*(struct in_addr *)host_entity->h_addr));

        (*addr_con).sin_family = host_entity->h_addrtype;
        (*addr_con).sin_port = htons (PORT_NO);
        (*addr_con).sin_addr.s_addr = *(long*)host_entity->h_addr;

        return ip;

}



char* reverse_dns_lookup(char *ip_addr)
{
        struct sockaddr_in temp_addr;
        socklen_t len;
        char buf[NI_MAXHOST], *ret_buf;

        temp_addr.sin_family = AF_INET;
        temp_addr.sin_addr.s_addr = inet_addr(ip_addr);
        len = sizeof(struct sockaddr_in);

        if (getnameinfo((struct sockaddr *) &temp_addr, len, buf,
                                        sizeof(buf), NULL, 0, NI_NAMEREQD))
        {
                printf("Could not resolve reverse lookup of hostname\n");
                return NULL;
        }
        ret_buf = (char*)malloc((strlen(buf) +1)*sizeof(char) );
        strcpy(ret_buf, buf);
        return ret_buf;
}



void send_ping(int ping_sockfd, struct sockaddr_in *ping_addr,
                                char *ping_dom, char *ping_ip, char *rev_host)
{
        int ttl_val=64, msg_count=0, i, addr_len, flag=1,
                        msg_received_count=0;

        struct ping_pkt pckt;
        struct sockaddr_in r_addr;
        struct timespec time_start, time_end, tfs, tfe;
        long double rtt_msec=0, total_msec=0;
        struct timeval tv_out;
        tv_out.tv_sec = RECV_TIMEOUT;
        tv_out.tv_usec = 0;

        clock_gettime(CLOCK_MONOTONIC, &tfs);


        // set socket options at ip to TTL and value to 64,
        // change to what you want by setting ttl_val
        if (setsockopt(ping_sockfd, SOL_IP, IP_TTL,
                        &ttl_val, sizeof(ttl_val)) != 0)
        {
                printf("\nSetting socket option to TTL failed!\n");
                return;
        }

        else
        {
                printf("\nSocket set to TTL..\n");
        }

        // setting timeout of recv setting
        setsockopt(ping_sockfd, SOL_SOCKET, SO_RCVTIMEO,
                                (const char*)&tv_out, sizeof tv_out);

        // send icmp packet in an infinite loop
        while(pingloop)
        {
                                 // flag is whether packet was sent or not
                flag=1;

                //filling packet
                bzero(&pckt, sizeof(pckt));

                pckt.hdr.type = ICMP_ECHO;
                pckt.hdr.un.echo.id = getpid();

                for ( i = 0; i < sizeof(pckt.msg)-1; i++ )
                        pckt.msg[i] = i+'0';

                pckt.msg[i] = 0;
                pckt.hdr.un.echo.sequence = msg_count++;
                pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));


                usleep(PING_SLEEP_RATE);

                //send packet
                clock_gettime(CLOCK_MONOTONIC, &time_start);
                if ( sendto(ping_sockfd, &pckt, sizeof(pckt), 0,
                (struct sockaddr*) ping_addr,
                        sizeof(*ping_addr)) <= 0)
                {
                        printf("\nPacket Sending Failed!\n");
                        flag=0;
                }

                //receive packet
                addr_len=sizeof(r_addr);

                if ( recvfrom(ping_sockfd, &pckt, sizeof(pckt), 0,
                        (struct sockaddr*)&r_addr, &addr_len) <= 0
                        && msg_count>1)
                {
                        printf("\nPacket receive failed!\n");
                }
		else
                {
                        clock_gettime(CLOCK_MONOTONIC, &time_end);

                        double timeElapsed = ((double)(time_end.tv_nsec -time_start.tv_nsec))/1000000.0;
                                rtt_msec = (time_end.tv_sec-time_start.tv_sec) * 1000.0 + timeElapsed;

                        // if packet was not sent, don't receive
                        if(flag)
                        {
                                if(!(pckt.hdr.type ==69 && pckt.hdr.code==0))
                                {
                                        printf("Error..Packet received with ICMPtype %d code %d\n",pckt.hdr.type, pckt.hdr.code);
                                }
                                else
                                {
                                        printf("%d bytes from %s (h: %s)(%s) msg_seq=%d ttl=%drtt = %Lf ms.\n", PING_PKT_S, ping_dom, rev_host, ping_ip, msg_count,ttl_val, rtt_msec);

                                        msg_received_count++;
                                }
                        }
                }
        }
        clock_gettime(CLOCK_MONOTONIC, &tfe);
        double timeElapsed = ((double)(tfe.tv_nsec - tfs.tv_nsec))/1000000.0;

        total_msec = (tfe.tv_sec-tfs.tv_sec)*1000.0+timeElapsed;

        printf("\n===%s ping statistics===\n", ping_ip);
        printf("\n%d packets sent, %d packets received, %f percentpacket loss. Total time: %Lf ms.\n\n",
                msg_count, msg_received_count,((msg_count - msg_received_count)/msg_count) * 100.0,total_msec);
}


int pingping(ip_){
	int sockfd;
        char *ip_addr, *reverse_hostname;
        struct sockaddr_in addr_con;
        int addrlen = sizeof(addr_con);
        char net_buf[NI_MAXHOST];

        ip_addr = dns_lookup(ip_, &addr_con);
        if(ip_addr==NULL)
        {
                printf("\nDNS lookup failed! Couldnot resolve hostname!\n");
                return 0;
        }

        reverse_hostname = reverse_dns_lookup(ip_addr);
        printf("\nTrying to connect to '%s' IP: %s\n",ip_, ip_addr);
        printf("\nReverse Lookup domain: %s",reverse_hostname);

        //socket()
        sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if(sockfd<0)
        {
                printf("\nSocket file descriptor not received!!\n");
             return 0;
        }
        else
                        printf("\nSocket file descriptor %d received\n", sockfd);
	signal(SIGINT, intHandler);//catching interrupt

        //send pings continuously
        send_ping(sockfd, &addr_con, reverse_hostname, ip_addr, ip_);


        return 0;
}





int main(int argc, const char **argv) {
    int ret = -1;
    if (argc != 3) {
        printf("Usage: %s <INTERFACE> <DEST_IP>\n", argv[0]);
        return 1;
    }
    const char *ifname = argv[1];
    const char *ip = argv[2];
    char *ip_ = strdup(argv[2]);
    return test_arping(ifname, ip);
    return pingping(ip_);
	


}
