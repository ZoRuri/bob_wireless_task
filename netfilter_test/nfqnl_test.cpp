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

#include <string.h>

//void http_request_parser();

#define HTTP_FILED_NAME  1
#define HTTP_FILED_VALUE 2

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

int HTTP_field_parser(u_char *buf, HTTP_Request_Header *reqHeader, int len) {
    reqHeader->filed.name = "";
    reqHeader->filed.value = "";

    int i = 0;

    int type = HTTP_FILED_NAME;

    for (i = 0; i < len; ++i)
    {
        if( buf[i] == '\r' && buf[i + 1] == '\n' )  {
            i += 2;
            break;
        }

        if ( buf[i] == ':' && buf [i + 1] == ' ') {
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

void dump(unsigned char *buf, int len) {
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

            if (strcmp("Host", reqHeader.filed.name.c_str()) == 0)
                clog << reqHeader.filed.value << endl;

            //printf("len: %d %d\n", len, offset);
        }

    }

//    int i;

//    for (i = 0; i < len; ++i) {
//        if((i % 16) == 0)
//            printf("\n");
//        printf("%02X", buf[i]);
//        printf(" ");
//    }

    printf("\n");
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
    if (ret >= 0) {
        dump(data, ret);
        printf("payload_len=%d ", ret);
    }

	fputc('\n', stdout);

	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

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
