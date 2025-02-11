#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <signal.h>

/*
 * PiDecrypt - Receiver Decryption
 *
 * This daemon intercepts incoming IPv4 packets, locates the TCP/UDP payload,
 * and attempts to decrypt it with AES-256-GCM. It expects that the last 16
 * bytes of the payload are the GCM authentication tag.
 *
 * For demonstration:
 *   - We use the same static key/IV as PiCrypt.
 *   - We only parse IPv4 + TCP/UDP. Other protocols pass unmodified.
 *   - Fragmentation not handled. Large or fragmented packets may break.
 *   - We recalc checksums after decrypting.
 *
 * Minimal usage:
 *   1) Compile: gcc -o PiDecrypt PiDecrypt.c -lnetfilter_queue -lcrypto -lssl
 *   2) Run: sudo ./PiDecrypt
 *   3) iptables rule (on the receiving side):
 *      sudo iptables -A INPUT -j NFQUEUE --queue-num 0
 *
 * Disclaimers:
 *   - This code is for DEMO only.
 *   - In production, you must handle IP/TCP/UDP headers carefully.
 *   - Use at your own risk.
 */

// AES-256-GCM parameters
#define AES_KEY_SIZE 32
#define AES_IV_SIZE  16
#define GCM_TAG_SIZE 16

static unsigned char s_key[AES_KEY_SIZE] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
    0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20
};

static unsigned char s_iv[AES_IV_SIZE] = {
    0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
};

static int running = 1;

// IP header (simplified)
struct ip_header {
    unsigned char  ihl:4;
    unsigned char  version:4;
    unsigned char  tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char  ttl;
    unsigned char  protocol;
    unsigned short check;
    unsigned int   saddr;
    unsigned int   daddr;
};

// Minimal TCP header
struct tcp_header {
    unsigned short source;
    unsigned short dest;
    unsigned int   seq;
    unsigned int   ack_seq;
    unsigned char  doff:4;
    unsigned char  res1:4;
    unsigned char  flags;
    unsigned short window;
    unsigned short check;
    unsigned short urg_ptr;
};

// Minimal UDP header
struct udp_header {
    unsigned short source;
    unsigned short dest;
    unsigned short len;
    unsigned short check;
};

/////////////////////////////////////////////////////////////////
// Recompute IP checksum
/////////////////////////////////////////////////////////////////
static unsigned short ip_checksum(unsigned short *buf, int len)
{
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        unsigned short tmp = 0;
        *(unsigned char*)(&tmp) = *(unsigned char*)buf;
        sum += tmp;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

/////////////////////////////////////////////////////////////////
// Recompute TCP/UDP checksums (pseudo-header)
/////////////////////////////////////////////////////////////////
static unsigned short transport_checksum(unsigned short *buf,
                                         int len,
                                         unsigned int src_ip,
                                         unsigned int dst_ip,
                                         unsigned char proto)
{
    unsigned long sum = 0;

    // Pseudo-header fields
    sum += (src_ip >> 16) & 0xffff;
    sum += (src_ip) & 0xffff;
    sum += (dst_ip >> 16) & 0xffff;
    sum += (dst_ip) & 0xffff;

    sum += htons(proto);
    sum += htons(len);

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        unsigned short tmp = 0;
        *(unsigned char*)(&tmp) = *(unsigned char*)buf;
        sum += tmp;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (unsigned short)(~sum);
}

/////////////////////////////////////////////////////////////////
// AES-256-GCM Decryption
// ciphertext_len includes the GCM tag appended at the end
/////////////////////////////////////////////////////////////////
static int decrypt_gcm(const unsigned char *ciphertext,
                       int ciphertext_len,
                       unsigned char *plaintext)
{
    if (ciphertext_len < GCM_TAG_SIZE) {
        return -1;
    }

    int data_len = ciphertext_len - GCM_TAG_SIZE;
    const unsigned char *tag = ciphertext + data_len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "[PiDecrypt] EVP_CIPHER_CTX_new() failed\n");
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, s_key, s_iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int out_len = 0;
    int total_len = 0;

    // Decrypt data portion
    if (EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext, data_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len = out_len;

    // Set the GCM tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE, (void *)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Finalize (check authentication)
    if (EVP_DecryptFinal_ex(ctx, plaintext + total_len, &out_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += out_len;

    EVP_CIPHER_CTX_free(ctx);
    return total_len;
}

/////////////////////////////////////////////////////////////////
// Intercept inbound packets, decrypt TCP/UDP payload if present
/////////////////////////////////////////////////////////////////
static int packet_callback(struct nfq_q_handle *qh,
                           struct nfgenmsg *nfmsg,
                           struct nfq_data *nfa,
                           void *data)
{
    (void)nfmsg;
    (void)data;

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) {
        // No header
        return nfq_set_verdict(qh, 0, NF_ACCEPT, 0, NULL);
    }

    unsigned char *pkt = NULL;
    int pkt_len = nfq_get_payload(nfa, &pkt);
    if (pkt_len < 0) {
        return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
    }

    if ((size_t)pkt_len < sizeof(struct ip_header)) {
        return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
    }

    struct ip_header *iph = (struct ip_header *)pkt;
    if (iph->version != 4) {
        // pass non-IPv4
        return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
    }

    int ip_hdr_len = iph->ihl * 4;
    if (pkt_len < ip_hdr_len) {
        return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
    }

    // Only decrypt TCP or UDP
    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) {
        return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
    }

    unsigned short tot_len = ntohs(iph->tot_len);
    if (tot_len > pkt_len) {
        // Malformed
        return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
    }

    unsigned char *trans_hdr = pkt + ip_hdr_len;
    int trans_len = tot_len - ip_hdr_len;

    if (iph->protocol == IPPROTO_TCP) {
        if (trans_len < (int)sizeof(struct tcp_header)) {
            return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
        }
        struct tcp_header *tcph = (struct tcp_header*)trans_hdr;
        int tcp_hdr_len = tcph->doff * 4;
        if (trans_len < tcp_hdr_len) {
            return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
        }
        unsigned char *payload = trans_hdr + tcp_hdr_len;
        int payload_len = trans_len - tcp_hdr_len;
        if (payload_len > GCM_TAG_SIZE) {
            // Attempt decrypt
            unsigned char *plainbuf = malloc(payload_len);
            if (!plainbuf) {
                return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
            }
            int dec_len = decrypt_gcm(payload, payload_len, plainbuf);
            if (dec_len > 0) {
                int size_diff = dec_len - payload_len;
                if (pkt_len + size_diff > 65535) {
                    free(plainbuf);
                    return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
                }

                // Move trailing data if packet shrinks or grows
                memmove(payload + dec_len,
                        payload + payload_len,
                        pkt_len - (payload + payload_len - pkt));

                pkt_len += size_diff;
                iph->tot_len = htons(tot_len + size_diff);

                memcpy(payload, plainbuf, dec_len);
                free(plainbuf);

                // Recompute TCP checksum
                tcph->check = 0;
                unsigned short tcp_sum = transport_checksum((unsigned short*)trans_hdr,
                                                           trans_len + size_diff,
                                                           iph->saddr,
                                                           iph->daddr,
                                                           iph->protocol);
                tcph->check = tcp_sum;

                // Recompute IP checksum
                iph->check = 0;
                unsigned short ip_sum = ip_checksum((unsigned short*)iph, ip_hdr_len);
                iph->check = ip_sum;

                return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
            } else {
                // Decryption failed, pass as is
                free(plainbuf);
                return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
            }
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        if (trans_len < (int)sizeof(struct udp_header)) {
            return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
        }
        struct udp_header *udph = (struct udp_header*)trans_hdr;
        int udp_hdr_len = sizeof(struct udp_header);
        unsigned char *payload = trans_hdr + udp_hdr_len;
        int payload_len = trans_len - udp_hdr_len;
        if (payload_len > GCM_TAG_SIZE) {
            unsigned char *plainbuf = malloc(payload_len);
            if (!plainbuf) {
                return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
            }
            int dec_len = decrypt_gcm(payload, payload_len, plainbuf);
            if (dec_len > 0) {
                int size_diff = dec_len - payload_len;
                if (pkt_len + size_diff > 65535) {
                    free(plainbuf);
                    return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
                }

                memmove(payload + dec_len,
                        payload + payload_len,
                        pkt_len - (payload + payload_len - pkt));

                pkt_len += size_diff;
                iph->tot_len = htons(tot_len + size_diff);

                memcpy(payload, plainbuf, dec_len);
                free(plainbuf);

                // Update UDP length
                udph->len = htons(ntohs(udph->len) + size_diff);

                // Recompute UDP checksum
                udph->check = 0;
                unsigned short udp_sum = transport_checksum((unsigned short*)udph,
                                                           trans_len + size_diff,
                                                           iph->saddr,
                                                           iph->daddr,
                                                           iph->protocol);
                udph->check = udp_sum;

                // Recompute IP checksum
                iph->check = 0;
                unsigned short ip_sum = ip_checksum((unsigned short*)iph, ip_hdr_len);
                iph->check = ip_sum;

                return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
            } else {
                free(plainbuf);
                return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
            }
        }
    }

    // If no payload or decryption fails, pass unmodified
    return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
}

static void handle_signal(int signum)
{
    (void)signum;
    running = 0;
}

int main(void)
{
    ERR_load_crypto_strings();

    printf("[PiDecrypt] Starting. Press Ctrl+C to exit.\n");
    signal(SIGINT, handle_signal);

    // Initialize netfilter queue
    struct nfq_handle *h = nfq_open();
    if (!h) {
        fprintf(stderr, "[PiDecrypt] nfq_open() failed\n");
        return 1;
    }

    nfq_unbind_pf(h, AF_INET);
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "[PiDecrypt] nfq_bind_pf(AF_INET) failed\n");
        nfq_close(h);
        return 1;
    }

    // Create queue #0
    struct nfq_q_handle *qh = nfq_create_queue(h, 0, &packet_callback, NULL);
    if (!qh) {
        fprintf(stderr, "[PiDecrypt] nfq_create_queue() failed\n");
        nfq_close(h);
        return 1;
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "[PiDecrypt] nfq_set_mode() failed\n");
        nfq_destroy_queue(qh);
        nfq_close(h);
        return 1;
    }

    int fd = nfq_fd(h);
    unsigned char buf[65536];

    while (running) {
        ssize_t rv = recv(fd, buf, sizeof(buf), 0);
        if (rv > 0) {
            nfq_handle_packet(h, (char*)buf, rv);
        } else if (rv < 0 && running) {
            perror("[PiDecrypt] recv");
            break;
        }
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    ERR_free_strings();

    printf("[PiDecrypt] Exiting...\n");
    return 0;
}
