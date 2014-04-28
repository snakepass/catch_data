// loop.cpp: 

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <time.h>
#include <stdlib.h>
#include <pcap.h>
#include <iostream>
#include <string.h>

#include "parse_pkt.h"
#include "tcp.h"
#include "udp.h"
#include "ip.h"
#include "def.h"
#include "extern.h"

using namespace std;

inline void parse_udp (const struct pcap_pkthdr *pkt_hdr, const u_char *pkt, struct IP *ip_pkt)
{
    struct UDPHDR *udppkt = (struct UDPHDR*)(pkt + g_datalink_size + IP_SIZE);
    u_char *payload = (u_char *)(pkt + g_datalink_size + IP_SIZE + sizeof(*udppkt));
    unsigned payload_len = pkt_hdr->len - (int)( payload - pkt );
    if (payload_len == 0)
        return;

    unsigned source = ntohs (udppkt->source);
    unsigned dest = ntohs (udppkt->dest);
#ifndef DEBUG
    char ip_src[16], ip_dst[16];
    sprintf (ip_src, "%s", inet_ntoa (ip_pkt->ip_src));
    sprintf (ip_dst, "%s", inet_ntoa (ip_pkt->ip_dst));
    cout << "udp from " << ip_src << ":" << source << " to " << ip_dst << ":" << dest << endl;
#endif
    ParsePkt2::get_instance ()->add_pkt (payload, payload_len
                , ip_pkt->ip_src, ip_pkt->ip_dst, source, dest);
}

void parse_tcp (const struct pcap_pkthdr *pkt_hdr, const u_char *pkt, struct IP *ip_pkt, int id)
{
    cout << "got tcp pkt" << endl;
    struct TCPHDR *tcppkt = (struct TCPHDR*)(pkt + g_datalink_size + IP_SIZE);
    int tcp_size = tcppkt->doff * 4;
    u_char *payload = (u_char *)(pkt + g_datalink_size + IP_SIZE + tcp_size);
    //u_char *payload = (u_char*)(pkt + g_datalink_size + IP_SIZE + tcp_size);
    unsigned payload_len = g_ip_len - IP_SIZE - tcp_size;
    cout << "tcp payload len " << payload_len << endl;
    char ip_src[16], ip_dst[16];
    sprintf (ip_src, "%s", inet_ntoa (ip_pkt->ip_src));
    sprintf (ip_dst, "%s", inet_ntoa (ip_pkt->ip_dst));
    cout << "tcp from " << ip_src << ":" << ntohs(tcppkt->source)
        << " to " << ip_dst << ":" << ntohs(tcppkt->dest) << endl;

    //unsigned source = ntohs (tcppkt->source);
    //unsigned dest = ntohs (tcppkt->dest);

    if(!payload_len){
        return ;
    } else if((!strncmp((const char *)payload,"HTTP",4))||(!strncmp((const char *)payload,"GET",3)))
    {
        char fname[255];
        sprintf(fname, "data/vs_%s:%d_%s:%d.tcp.%d", inet_ntoa(ip_pkt->ip_src), ntohs(tcppkt->source)
                , inet_ntoa(ip_pkt->ip_dst), ntohs(tcppkt->dest), 1);
        FILE *fp = fopen(fname, "a");
        fwrite (payload, sizeof(u_char), payload_len, fp);
        fclose (fp);
    } else {
    //    ParsePkt2::get_instance ()->add_pkt (payload, payload_len, ip_pkt->ip_src, ip_pkt->ip_dst, source, dest);
        char fname2[255];
        sprintf(fname2, "data/vs_%s:%d_%s:%d.tcp.%d", inet_ntoa(ip_pkt->ip_src), ntohs(tcppkt->source)
                , inet_ntoa(ip_pkt->ip_dst), ntohs(tcppkt->dest), 2);
        FILE *fp2 = fopen(fname2, "a");
        fwrite (payload, sizeof(u_char), payload_len, fp2);
        fclose (fp2);
    }

/*
    char fname2[255];
    sprintf(fname2, "data/vs_%s:%d_%s:%d.tcp.%d", inet_ntoa(ip_pkt->ip_src), ntohs(tcppkt->source)
            , inet_ntoa(ip_pkt->ip_dst), ntohs(tcppkt->dest), 2);
    FILE *fp2 = fopen(fname2, "a");
    fprintf (fp2, "seq: %u\n", ntohl(tcppkt->seq));
    fprintf (fp2, "ack seq: %u\n", ntohl(tcppkt->ack_seq));
    fprintf (fp2, "doff: %u\n", (tcppkt->doff));
    fprintf (fp2, "fin: %u\n", (tcppkt->fin));
    fprintf (fp2, "syn: %u\n", (tcppkt->syn));
    fprintf (fp2, "ack %u\n", (tcppkt->ack));
    fprintf (fp2, "==========================\n");
    fclose (fp2);
*/
}

void get_pkt (u_char *arg, const struct pcap_pkthdr *pkt_hdr, const u_char *pkt)
{
    struct IP *ip_pkt = (struct IP*)(pkt + g_datalink_size);
#if __BYTE_ORDER == __LITTLE_ENDIAN
        g_ip_len = (ip_pkt->ip_len % 256) * 256 + (ip_pkt->ip_len) / 256;
#elif __BYTE_ORDER == __BIG_ENDIAN
        g_ip_len = ip_pkt->ip_len;
#else
# error "Please fix <bits/endian.h>"
#endif
    int *id = (int *)arg;  
    printf("=======================================\n");
    printf("id: %d\n", ++(*id));  
    printf("Packet length: %d\n", pkt_hdr->len);  
    printf("Number of bytes: %d\n", pkt_hdr->caplen);  
    printf("Recieved time: %s", ctime((const time_t *)&pkt_hdr->ts.tv_sec)); 

    switch (ip_pkt->ip_p) {
        case IPPROTO_TCP: {
            printf("this is TCP packet\n");
            parse_tcp (pkt_hdr, pkt, ip_pkt, *id);
            break;
        } case IPPROTO_UDP: {
            printf("this is UDP packet\n");
            parse_udp (pkt_hdr, pkt, ip_pkt);
            break;
        } default: /* Packet with an unidentified protocol */
#ifndef NDEBUG
            char ip_src[16], ip_dst[16];
            sprintf (ip_src, "%s", inet_ntoa (ip_pkt->ip_src));
            sprintf (ip_dst, "%s", inet_ntoa (ip_pkt->ip_dst));
            printf( "Packet with unidentified protocol %d caught: %s > %s\n",
                   ip_pkt->ip_p, ip_src, ip_dst);
#endif
            break;
        }
}

