#include <iostream>
#include <stdio.h>
#include <string>
#include <string.h>
#include <regex>
#include <unistd.h>
#include <netinet/in.h> //  struct in_addr
#include <arpa/inet.h> //  inet_addr (), inet_ntoa (), inet_aton () ...
#include <linux/types.h>
#include <linux/netfilter.h>
#include <map>
#include <errno.h>
#include <netinet/in_systm.h>
#define LIBNET_LIL_ENDIAN 1
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "flowmanage.h"
#include "header.h"


using namespace std;

static uint32_t flag = 0;
static uint32_t new_data_len;
static string from_string, too_string;
static uint8_t* new_data;
static map<flowmanage, uint32_t> flow_check;

#pragma pack(push,1)
struct Pseudoheader{
    uint32_t srcIP;
    uint32_t destIP;
    uint8_t reserved=0;
    uint8_t protocol;
    uint16_t TCPLen;
};
#pragma pack(pop)

uint16_t calculate(uint16_t* data, int dataLen)
{
    uint32_t sum=0;
    while(dataLen>1){
        sum+=ntohs(*data++);
        dataLen-=2;
    }
    if(dataLen==1){
        sum+=ntohs((uint8_t)*data);
    }
    //sum = (sum >> 16) + (sum & 0xffff);
    sum = (sum >> 16) + (sum & 0xffff);
    return (uint16_t)sum;
}

uint16_t calTCPChecksum(uint8_t *data,int dataLen)
{
    struct Pseudoheader pseudoheader;

    //init Pseudoheader
    struct ipv4_hdr *iph=(struct ipv4_hdr*)data;
    struct tcp_hdr *tcph=(struct tcp_hdr*)(data+iph->ip_hl*4);

    pseudoheader.srcIP = iph->ip_src;
    pseudoheader.destIP = iph->ip_dst;
    pseudoheader.protocol=iph->ip_p;
    pseudoheader.TCPLen=htons(dataLen-(iph->ip_hl*4));

    //Cal pseudoChecksum
    uint16_t pseudoResult=calculate((uint16_t*)&pseudoheader,sizeof(pseudoheader));

    //Cal TCP Segement Checksum
    tcph->th_sum=0; //set Checksum field 0
    uint16_t tcpHeaderResult=calculate((uint16_t*)tcph,ntohs(pseudoheader.TCPLen));

    uint16_t checksum;
    uint32_t temp;
    temp = pseudoResult+tcpHeaderResult;
    //temp = (temp >> 16) + (temp & 0xffff);
    temp = (temp >> 16) + (temp & 0xffff);
    checksum = ntohs(~temp);
    tcph->th_sum=checksum;

    return checksum;
}

uint16_t calIPChecksum(uint8_t *data)
{
    struct ipv4_hdr *iph=(struct ipv4_hdr*)data;
    iph->ip_sum=0;

    uint16_t checksum=calculate((uint16_t*)iph,iph->ip_hl*4);
    iph->ip_sum = ntohs(~checksum);
    return checksum;
}

static uint32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    flag = 0;
    struct nfqnl_msg_packet_hdr *ph;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
            id = ntohl(ph->packet_id);
        }

    ret = nfq_get_payload(tb, &data);
    if(ret >= 0) {
        new_data = data;
        struct ipv4_hdr* iph = (struct ipv4_hdr *) data;
        if(iph->ip_p == IPPROTO_TCP){
            struct tcp_hdr* tcph = (struct tcp_hdr *)((uint8_t*)iph+iph->ip_hl*4);
            uint16_t payload_len =ntohs(iph->ip_len) - (iph->ip_hl*4) - (tcph->th_off*4);
            uint8_t* payload = (uint8_t*)tcph+tcph->th_off*4;
            uint16_t len = (iph->ip_hl * 4)+(tcph->th_off * 4);
            if(ntohs(tcph->th_sport) == 80 && payload_len>0){
                string s_data((char*)payload, payload_len);
                flowmanage flow{iph->ip_src, iph->ip_dst, tcph->th_sport, tcph->th_dport};
                map<flowmanage, uint32_t>::iterator iter, r_iter;
                iter = flow_check.find(flow);
                static regex pattern(from_string);
                smatch m;
                if(regex_search(s_data, m, pattern)){
                        s_data = regex_replace(s_data, pattern, too_string);
                        flow_check[flow] += s_data.length() - payload_len;
                        tcph->th_seq += htonl(iter->second);
                        memcpy(payload, s_data.c_str(), s_data.length());
                        calTCPChecksum(new_data , len + s_data.length());
                        new_data_len = len + s_data.length();
                        flag = 1;
                }

                flow.reverse(flow);
                r_iter = flow_check.find(flow);
                if(r_iter!=flow_check.end()) {
                    tcph->th_ack -= htonl(r_iter->second);
                    calTCPChecksum(new_data ,ret);
                    new_data_len = ret;
                    flag = 1;
                }
            }
        }
    return id;
    }
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);

    if(flag == 0)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    else {
    printf("Changed!!\n");
    return nfq_set_verdict(qh, id, NF_ACCEPT, new_data_len, new_data);
    }
}
int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    if(argc != 3){
    printf("use : ./ip_change <before ip> <after ip>\n");
    return 0;
    }

    from_string = argv[1];
    too_string = argv[2];

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        printf("error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        printf("error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        printf("error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");

    qh = nfq_create_queue(h,  0, &cb, NULL);					// Queue create
    if (!qh) {
        printf("error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        printf("can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
 //           printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
