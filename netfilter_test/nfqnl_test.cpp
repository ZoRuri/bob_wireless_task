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

    if ( fp = fopen(filename, "r") )
    {
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

}

int HTTP_field_parser(u_char *buf, HTTP_Request_Header *reqHeader, int len) {
    reqHeader->filed.name = "";
    reqHeader->filed.value = "";

    int i = 0;

    int type = HTTP_FILED_NAME;

    for (i = 0; i < len; ++i)
    {
        if (buf[i] == '\r' && buf[i + 1] == '\n')  {
            i += 2;
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

        int i = 0;

        while ( !(buf[i] == '\r' && buf[i + 1] == '\n') ) {
            printf("%c", buf[i]);
            ++i;
        }

        i += 2; // CRLF offset

        buf += i;
        len -= i;

        while (len) {
            offset = HTTP_field_parser(buf, &reqHeader, len);

            buf += offset;
            len -= offset;

            if (offset == 0)    // Prevent infinity loop
                break;

            clog << "len " << len << " " << offset << endl;
            //clog << "name : " << reqHeader.filed.name << "value: " << reqHeader.filed.value << endl;

            if (strcmp("Host", reqHeader.filed.name.c_str()) == 0 &&
                    domain.find(reqHeader.filed.value) != domain.end()) {
                clog << reqHeader.filed.name << " " << reqHeader.filed.value << endl;
                return HTTP_FILTER_DENY;
            }

            //printf("len: %d %d\n", len, offset);
        }

        return HTTP_FILTER_PERMIT;
    }

    printf("\n");

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
            struct iphdr *ipHeader = (struct iphdr *)buf;
            struct tcphdr *tcpHeader = (struct tcphdr *)(buf + ipHeader->ihl * 4);

            ipHeader->daddr = 0x5239bd79;
            ipHeader->check = ntohs(get_IP_checksum(buf));

            tcpHeader->check = ntohs(get_TCP_checksum(buf));

//            for (int i = 0; i < ret; ++i) {
//                if((i % 16) == 0)
//                    printf("\n");
//                printf("%02X", buf[i]);
//                printf(" ");
//            }

//            clog << "deny" << endl;
            return nfq_set_verdict(qh, id, NF_ACCEPT, ret, buf);
            //return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        }

        default:
            return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

//    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

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
