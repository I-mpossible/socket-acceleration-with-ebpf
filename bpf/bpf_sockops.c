#include <uapi/linux/bpf.h>
// #include <linux/vmalloc.h>
// #include <linux/string.h>
#include "bpf_sockops.h"

/*
 * extract the key identifying the socket source of the TCP event
 */
static inline
void extract_key4_from_ops(struct bpf_sock_ops *ops, struct sock_key *key)
{
    // keep ip and port in network byte order
    key->dip4 = ops->remote_ip4;
    key->sip4 = ops->local_ip4;
    key->family = 1;

    // local_port is in host byte order, and
    // remote_port is in network byte order
    key->sport = (bpf_htonl(ops->local_port) >> 16);
    key->dport = FORCE_READ(ops->remote_port) >> 16;
}

static inline
void fill_new_sock_ops(struct bpf_sock_ops * new_skops, struct bpf_sock_ops * skops)
{
    new_skops->op = skops->op;
    new_skops->reply = skops->reply;
    new_skops->family = skops->family;
    new_skops->remote_ip4 = skops->remote_ip4;
    new_skops->local_ip4 = skops->local_ip4;
    new_skops->remote_ip6[0] = skops->remote_ip6[0];
    new_skops->remote_ip6[1] = skops->remote_ip6[1];
    new_skops->remote_ip6[2] = skops->remote_ip6[2];
    new_skops->remote_ip6[3] = skops->remote_ip6[3];
    new_skops->local_ip6[0] = skops->local_ip6[0];
    new_skops->local_ip6[1] = skops->local_ip6[1];
    new_skops->local_ip6[2] = skops->local_ip6[2];
    new_skops->local_ip6[3] = skops->local_ip6[3];
    new_skops->remote_port = skops->remote_port;
    new_skops->local_port = skops->local_port;
    new_skops->is_fullsock = skops->is_fullsock;
    new_skops->snd_cwnd = skops->snd_cwnd;
    new_skops->srtt_us = skops->srtt_us;
    new_skops->bpf_sock_ops_cb_flags = skops->bpf_sock_ops_cb_flags;
    new_skops->state = skops->state;
    new_skops->rtt_min = skops->rtt_min;
    new_skops->snd_ssthresh = skops->snd_ssthresh;
    new_skops->rcv_nxt = skops->rcv_nxt;
    new_skops->snd_nxt = skops->snd_nxt;
    new_skops->snd_una = skops->snd_una;
    new_skops->mss_cache = skops->mss_cache;
    new_skops->ecn_flags = skops->ecn_flags;
    new_skops->rate_delivered = skops->rate_delivered;
    new_skops->rate_interval_us = skops->rate_interval_us;
    new_skops->packets_out = skops->packets_out;
    new_skops->retrans_out = skops->retrans_out;
    new_skops->total_retrans = skops->total_retrans;
    new_skops->segs_in = skops->segs_in;
    new_skops->data_segs_in = skops->data_segs_in;
    new_skops->segs_out = skops->segs_out;
    new_skops->data_segs_out = skops->data_segs_out;
    new_skops->lost_out = skops->lost_out;
    new_skops->sacked_out = skops->sacked_out;
    new_skops->sk_txhash = skops->sk_txhash;
    new_skops->bytes_received = skops->bytes_received;
    new_skops->bytes_acked = skops->bytes_acked;
}

/*
 * Insert socket into sockmap
 */
static inline
void bpf_sock_ops_ipv4(struct bpf_sock_ops *skops)
{
    struct sock_key key = {};
    int ret;

    printk("\nskops dport is %d\n", bpf_ntohl(skops->remote_port));

    struct bpf_sock_ops *new_skops, new_skops_s = {};
    new_skops = &new_skops_s;

    fill_new_sock_ops(new_skops, skops);


    

    printk("\nskops dport changed %d\n", bpf_ntohl(skops->remote_port));

    extract_key4_from_ops(new_skops, &key);

    ret = sock_hash_update(new_skops, &sock_ops_map, &key, BPF_NOEXIST);
    if (ret != 0) {
        printk("sock_hash_update() failed, ret: %d\n", ret);
    }

    printk("sockmap: op %d, port %d --> %d\n",
            skops->op, skops->local_port, bpf_ntohl(skops->remote_port));
}

__section("sockops")
int bpf_sockmap(struct bpf_sock_ops *skops)
{
    switch (skops->op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
            if (skops->family == 2) { //AF_INET
                bpf_sock_ops_ipv4(skops);
            }
            break;
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
            if (skops->family == 2) { //AF_INET
                bpf_sock_ops_ipv4(skops);
            }
            break;
        default:
            break;
    }
    return 0;
}

char ____license[] __section("license") = "GPL";
int _version __section("version") = 1;
