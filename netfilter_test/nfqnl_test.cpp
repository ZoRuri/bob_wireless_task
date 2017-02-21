#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <iostream>
#include <bitset>
#include <set>

#include <string.h>
#include <arpa/inet.h>

#define HTTP_FILED_NAME  1
#define HTTP_FILED_VALUE 2

#define HTTP_FILED_NAME  1
#define HTTP_FILED_VALUE 2

#define NOT_HTTP_PACKET    0
#define HTTP_FILTER_PERMIT 1
#define HTTP_FILTER_DENY   2

using namespace std;

struct HTTP_Filed {
    string name;
    string value;
};

typedef struct HTTP_Request_Header {
    string method;
    string URI;
    string version;

    struct HTTP_Filed filed;
}HTTP_Request_Header;

set<string> domain;

uint16_t get_IP_checksum(unsigned char *buf) {
    struct iphdr *ipHeader = (struct iphdr *)buf;

    int len = (ipHeader->ihl * 4);

    ipHeader->check = 0x0000;

    uint32_t ipChecksum = 0;

    for (int i = 0; i < len; ++i) {
        if (i & 1)
            ipChecksum += buf[i];
        else
            ipChecksum += (buf[i] << 8);
    }

    do {
        ipChecksum += ipChecksum >> 16;
        ipChecksum &= 0xffff;
    } while(ipChecksum > 0xffff);

    return (uint16_t)ipChecksum ^ 65535;
}

uint16_t get_TCP_checksum(unsigned char *buf) {
    struct iphdr *ipHeader = (struct iphdr *)buf;
    struct tcphdr *tcpHeader = (struct tcphdr *)(buf + ipHeader->ihl * 4);

    int segmentLen = ntohs(ipHeader->tot_len) - ipHeader->ihl * 4;

    tcpHeader->check = 0x0000;

    /* Pseudo Header */
    uint32_t pseudoSum = 0;

    pseudoSum += (ntohl(ipHeader->saddr) >> 16) + (ntohl(ipHeader->saddr) & 0xffff);
    pseudoSum += (ntohl(ipHeader->daddr) >> 16) + (ntohl(ipHeader->daddr) & 0xffff);
    pseudoSum += ipHeader->protocol;    // reserved (always 0) + protocol
    pseudoSum += segmentLen;            // TCP header length + data length

    /* TCP Segment */
    uint32_t segmentSum = 0;

    int totLen = ntohs(ipHeader->tot_len);
    int ihl = ipHeader->ihl * 4;

    for (int i = ihl; i < totLen; ++i) {
        if (i & 1)
            segmentSum += buf[i];
        else
            segmentSum += (buf[i] << 8);
    }

    /* Checksum */
    uint32_t checksum = 0;

    checksum = pseudoSum + segmentSum;

    do {
        checksum += checksum >> 16;
        checksum &= 0xffff;
    } while(checksum > 0xffff);

    return (uint16_t)checksum ^ 65535;
}

void rule_parser(const char *filename) {
    FILE *fp;
    char str[1024];

    string temp = "";

    if ( (fp = fopen(filename, "r")) == NULL ) {
        perror("fopen error");
        exit(1);
    }

    while ( fread(str, 1, 1, fp) ) {
        if ( strcmp(str, "\n") == 0 ) {
            domain.insert(temp);
            temp = "";
        } else {
            temp.append(str);
        }
    }

    fclose(fp);

}

int HTTP_reqLine_parser(u_char *buf, HTTP_Request_Header *reqHeader, int len) {
    int i = 0;

    while (buf[i] != ' ') {
        reqHeader->method += buf[i];
        ++i;
        if (i > len)
            return -1;
    }

    ++i;    // SP offset

    while (buf[i] != ' ') {
        reqHeader->URI += buf[i];
        ++i;
        if (i > len)
            return -1;
    }

    ++i;    // SP offset

    while ( !(buf[i] == '\r' && buf[i + 1] == '\n') ) {
        reqHeader->version += buf[i];
        ++i;
        if (i > len)
            return -1;
    }

    i += 2; // CRLF offset

    return i;
}

int HTTP_field_parser(u_char *buf, HTTP_Request_Header *reqHeader, int len) {
    reqHeader->filed.name = "";
    reqHeader->filed.value = "";

    int i = 0;

    int type = HTTP_FILED_NAME;

    for (i = 0; i < len; ++i)
    {
        if (buf[i] == '\r' && buf[i + 1] == '\n')  {
            i += 2; // CRLF offset
            break;
        }

        if (buf[i] == ':' && buf [i + 1] == ' ') {
            i += 2;
            type = HTTP_FILED_VALUE;
        }

        if (type & HTTP_FILED_VALUE)
            reqHeader->filed.value += buf[i];
        else if (type & HTTP_FILED_NAME)
            reqHeader->filed.name += buf[i];
    }

    return i;
}

int HTTP_filter(unsigned char *buf, int len) {
    struct iphdr *ipHeader = (struct iphdr *)buf;
    struct tcphdr *tcpHeader = (struct tcphdr *)(buf + ipHeader->ihl * 4);

    uint totalLen = ntohs(ipHeader->tot_len);

    uint offset = (ipHeader->ihl * 4) + (tcpHeader->doff * 4);

    printf("version: %d length: %d sport: %d dport: %d offset: %d total: %d\n",
           ipHeader->version, ipHeader->ihl * 4, ntohs(tcpHeader->source), ntohs(tcpHeader->dest), offset, totalLen);

    /* Not only TCP */
    if (offset < totalLen) {
        buf += offset;
        len -= offset;

        HTTP_Request_Header reqHeader;

        offset = HTTP_reqLine_parser(buf, &reqHeader, len);

        /* if NOT HTTP PACKET */
        if (reqHeader.method.empty() && reqHeader.URI.empty() &&
                reqHeader.version.empty()) {
            return NOT_HTTP_PACKET;
        }

        clog << reqHeader.method << " " << reqHeader.URI << " " << reqHeader.version << endl;

        buf += offset;
        len -= offset;

        while (len) {
            offset = HTTP_field_parser(buf, &reqHeader, len);

            buf += offset;
            len -= offset;

            if (offset == 0)    // Prevent infinity loop
                break;

            if (strcmp("Host", reqHeader.filed.name.c_str()) == 0 &&
                    domain.find(reqHeader.filed.value) != domain.end()) {
                return HTTP_FILTER_DENY;
            }

        }

        return HTTP_FILTER_PERMIT;
    }

    return NOT_HTTP_PACKET;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
    u_int32_t id;

    int filterRet;

    struct nfqnl_msg_packet_hdr *ph;

    int ret;

    unsigned char *buf;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, id);
    }

    ret = nfq_get_payload(nfa, &buf);
    if (ret >= 0) {
        filterRet = HTTP_filter(buf, ret);
        printf("payload_len=%d ", ret);
    }

    fputc('\n', stdout);

    switch (filterRet) {
        case HTTP_FILTER_PERMIT:
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

        case HTTP_FILTER_DENY:
        {
//            u_char buf2[] = {
//                0x45, 0x00, 0x00, 0x65, 0xfc, 0x48, 0x00, 0x00, 0xc4, 0x06, 0xbb, 0xc7, 0xce,
//                0x7d, 0xa4, 0x52, 0xc0, 0xa8, 0x0b, 0x0a, 0x00, 0x50, 0xd4, 0x43, 0x63, 0x71,
//                0xc2, 0xb0, 0x8b, 0x4e, 0xfe, 0xfc, 0x50, 0x19, 0x00, 0x00, 0x24, 0xe7, 0x00,
//                0x00, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30, 0x20, 0x33, 0x30, 0x32,
//                0x20, 0x52, 0x65, 0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x0d, 0x0a, 0x4c, 0x6f,
//                0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x68, 0x74, 0x74, 0x70, 0x3a,
//                0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x77, 0x61, 0x72, 0x6e, 0x69, 0x6e, 0x67,
//                0x2e, 0x6f, 0x72, 0x2e, 0x6b, 0x72, 0x0d, 0x0a, 0x0d, 0x0a
//            };

//            struct iphdr *ipHeader = (struct iphdr *)buf;
//            struct tcphdr *tcpHeader = (struct tcphdr *)(buf + ipHeader->ihl * 4);

//            struct iphdr *ipHeader2 = (struct iphdr *)buf2;
//            struct tcphdr *tcpHeader2 = (struct tcphdr *)(buf2 + ipHeader->ihl * 4);

//            ipHeader2->daddr = ipHeader->saddr;
//            ipHeader2->saddr = ipHeader->daddr;

//            tcpHeader2->source = tcpHeader->dest;
//            tcpHeader2->dest   = tcpHeader->source;

//            //ipHeader->daddr = 0x5239bd79;

//            ipHeader2->check = ntohs(get_IP_checksum(buf2));
//            tcpHeader2->check = ntohs(get_TCP_checksum(buf2));

//            int sockfd;
//            string request = "";
//            request+="GET / HTTP/1.1\r\n";
//            request+="Host: www.gilgil.net\r\n";
//            request+="\r\n";

//            if ( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
//                perror("socket error");
//                exit(1);
//            }

//            clog << "socket" << endl;

//            struct sockaddr_in servaddr;
//            servaddr.sin_family = AF_INET;
//            servaddr.sin_port   = htons(80);

//            int ret;

//            if ((ret = inet_pton(AF_INET, "61.73.111.238", &servaddr.sin_addr)) < 0)
//                exit(1);
//            else if (!ret)
//                exit(1);

//            clog << "inet_pton" << endl;

//            if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
//                perror("connect error");
//                exit(1);
//            }

//            clog << "connect" << endl;

//            if (send(sockfd, request.c_str(), request.length(), 0) != request.length()) {
//                perror("send error");
//                exit(1);
//            }

//            clog << "send" << endl;

            //return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
            //return nfq_set_verdict(qh, id, NF_ACCEPT, sizeof(buf2), buf2);
            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        }

        default:
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

//    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

}

void usage(char *name) {
    printf("Usage: %s <URL list file>\n", name);
    exit(1);
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

    if (argc != 2)
        usage(argv[0]);

    rule_parser(argv[1]);

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
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
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
