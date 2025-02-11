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
 * PiCrypt - Sender Encryption
 *
 * This daemon intercepts outgoing IPv4 packets via Netfilter Queue,
 * encrypts only the TCP/UDP payload using AES-256-GCM, and appends
 * a GCM tag at the end of that payload.
 *
 * For demonstration:
 *   - We use a static key/IV (below). In a real deployment, you'd want
 *     ephemeral keys or a secure key exchange.
 *   - We parse only basic IP + TCP/UDP headers. ICMP or other protocols
 *     are passed unmodified.
 *   - Fragmentation is not handled. Overly large packets might cause issues.
 *   - Checksums for IP and TCP/UDP are recalculated after encryption.
 *
 * Minimal user config:
 *   1) Compile: gcc -o PiCrypt PiCrypt.c -lnetfilter_queue -lcrypto -lssl
 *   2) Run: sudo ./PiCrypt
 *   3) iptables rule (on the sender side):
 *      sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
 *   4) On the receiving side, run PiDecrypt with a matching static key.
 *
 * Disclaimers:
 *   - This code is for DEMO only, not production.
 *   - Encryption of only the payload means the receiver must do the reverse.
 *   - Without PiDecrypt, your data might be unreadable.
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
// Recompute TCP or UDP checksum (pseudo-header approach)
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

////////////////////////////////////////////////////////////////////
// AES-256-GCM Encryption
////////////////////////////////////////////////////////////////////
static int encrypt_gcm(const unsigned char *plaintext,
                       int plaintext_len,
                       unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "[PiCrypt] EVP_CIPHER_CTX_new() failed\n");
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "[PiCrypt] EVP_EncryptInit_ex() failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_IV_SIZE, NULL) != 1) {
        fprintf(stderr, "[PiCrypt] Set IV length failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, s_key, s_iv) != 1) {
        fprintf(stderr, "[PiCrypt] EVP_EncryptInit_ex(key, iv) failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    int out_len = 0;
    int total_len = 0;

    // Encrypt plaintext
    if (EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, plaintext_len) != 1) {
        fprintf(stderr, "[PiCrypt] EVP_EncryptUpdate() failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len = out_len;

    // Finalize
    if (EVP_EncryptFinal_ex(ctx, ciphertext + total_len, &out_len) != 1) {
        fprintf(stderr, "[PiCrypt] EVP_EncryptFinal_ex() failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    total_len += out_len;

    // Get GCM tag
    unsigned char tag[GCM_TAG_SIZE];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag) != 1) {
        fprintf(stderr, "[PiCrypt] EVP_CIPHER_CTX_ctrl(GET_TAG) failed\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Append tag
    memcpy(ciphertext + total_len, tag, GCM_TAG_SIZE);
    total_len += GCM_TAG_SIZE;

    EVP_CIPHER_CTX_free(ctx);
    return total_len;
}

////////////////////////////////////////////////////////////////////
// Handler: Intercept outgoing packets, encrypt payload if TCP/UDP
////////////////////////////////////////////////////////////////////
static int packet_callback(struct nfq_q_handle *qh,
                           struct nfgenmsg *nfmsg,
                           struct nfq_data *nfa,
                           void *data)
{
    (void)nfmsg;
    (void)data;

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) {
        return nfq_set_verdict(qh, 0, NF_ACCEPT, 0, NULL);
    }

    // Packet
    unsigned char *pkt = NULL;
    int pkt_len = nfq_get_payload(nfa, &pkt);
    if (pkt_len < 0) {
        return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
    }

    // We assume at least IP header is present
    if ((size_t)pkt_len < sizeof(struct ip_header)) {
        // Not enough data for IP header
        return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
    }

    struct ip_header *iph = (struct ip_header *)pkt;
    if (iph->version != 4) {
        // Not IPv4, pass through
        return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
    }

    // IP header length in bytes
    int ip_hdr_len = iph->ihl * 4;
    if (pkt_len < ip_hdr_len) {
        // Malformed
        return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
    }

    // Only encrypt TCP or UDP
    if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) {
        // pass other protocols unmodified
        return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
    }

    unsigned short tot_len = ntohs(iph->tot_len);
    if (tot_len > pkt_len) {
        // Malformed length
        return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
    }

    // The transport header
    unsigned char *trans_hdr = pkt + ip_hdr_len;
    int trans_len = tot_len - ip_hdr_len;

    // Distinguish TCP vs UDP
    if (iph->protocol == IPPROTO_TCP) {
        if (trans_len < (int)sizeof(struct tcp_header)) {
            // not enough data
            return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
        }
        struct tcp_header *tcph = (struct tcp_header *)trans_hdr;
        int tcp_hdr_len = tcph->doff * 4;
        if (trans_len < tcp_hdr_len) {
            return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
        }
        // Payload starts after tcp_hdr_len
        unsigned char *payload = trans_hdr + tcp_hdr_len;
        int payload_len = trans_len - tcp_hdr_len;
        if (payload_len > 0) {
            // Allocate buffer for ciphertext
            unsigned char *ciphertext = malloc(payload_len + GCM_TAG_SIZE);
            if (!ciphertext) {
                return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
            }
            int enc_len = encrypt_gcm(payload, payload_len, ciphertext);
            if (enc_len > 0) {
                // Adjust packet size if needed
                int new_payload_len = enc_len;
                int size_diff = new_payload_len - payload_len;

                // Expand or shrink the packet in-place if possible (assuming no fragmentation)
                // In production, you'd handle fragmentation or reallocation carefully.

                // Move data after payload if we need to expand
                if (size_diff != 0) {
                    if (pkt_len + size_diff > 65535) {
                        // can't exceed max IP packet size
                        free(ciphertext);
                        return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
                    }
                    memmove(payload + new_payload_len,
                            payload + payload_len,
                            pkt_len - (payload + payload_len - pkt));

                    pkt_len += size_diff;
                    iph->tot_len = htons(tot_len + size_diff);
                }

                // Copy in ciphertext
                memcpy(payload, ciphertext, new_payload_len);
                free(ciphertext);

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
                // encryption error
                free(ciphertext);
                return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
            }
        }
    } else if (iph->protocol == IPPROTO_UDP) {
        if (trans_len < (int)sizeof(struct udp_header)) {
            // not enough data
            return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
        }
        struct udp_header *udph = (struct udp_header *)trans_hdr;
        int udp_hdr_len = sizeof(struct udp_header);
        unsigned char *payload = trans_hdr + udp_hdr_len;
        int payload_len = trans_len - udp_hdr_len;
        if (payload_len > 0) {
            unsigned char *ciphertext = malloc(payload_len + GCM_TAG_SIZE);
            if (!ciphertext) {
                return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
            }
            int enc_len = encrypt_gcm(payload, payload_len, ciphertext);
            if (enc_len > 0) {
                int new_payload_len = enc_len;
                int size_diff = new_payload_len - payload_len;

                if (pkt_len + size_diff > 65535) {
                    free(ciphertext);
                    return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
                }

                memmove(payload + new_payload_len,
                        payload + payload_len,
                        pkt_len - (payload + payload_len - pkt));

                pkt_len += size_diff;
                iph->tot_len = htons(tot_len + size_diff);

                // Copy ciphertext in
                memcpy(payload, ciphertext, new_payload_len);
                free(ciphertext);

                // Update UDP header length
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
                free(ciphertext);
                return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, pkt_len, pkt);
            }
        }
    }

    // If no payload or encryption failed, just pass as-is
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

    signal(SIGINT, handle_signal);

    // Initialize Netfilter queue
    struct nfq_handle *h = nfq_open();
    if (!h) {
        fprintf(stderr, "[PiCrypt] nfq_open() failed\n");
        return 1;
    }

    // Unbind existing nf_queue handler for AF_INET
    nfq_unbind_pf(h, AF_INET);

    // Bind nf_queue handler for AF_INET
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "[PiCrypt] nfq_bind_pf(AF_INET) failed\n");
        nfq_close(h);
        return 1;
    }

    // Create queue #0
    struct nfq_q_handle *qh = nfq_create_queue(h, 0, &packet_callback, NULL);
    if (!qh) {
        fprintf(stderr, "[PiCrypt] nfq_create_queue() failed\n");
        nfq_close(h);
        return 1;
    }

    // Copy entire packet
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "[PiCrypt] nfq_set_mode() failed\n");
        nfq_destroy_queue(qh);
        nfq_close(h);
        return 1;
    }

    printf("[PiCrypt] Running. Press Ctrl+C to exit...\n");

    int fd = nfq_fd(h);
    unsigned char buf[65536];

    while (running) {
        ssize_t rv = recv(fd, buf, sizeof(buf), 0);
        if (rv > 0) {
            nfq_handle_packet(h, (char*)buf, rv);
        } else if (rv < 0 && running) {
            perror("[PiCrypt] recv");
            break;
        }
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    ERR_free_strings();

    printf("[PiCrypt] Exiting...\n");
    return 0;
}
