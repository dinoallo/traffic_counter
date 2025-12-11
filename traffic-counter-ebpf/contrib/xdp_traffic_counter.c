#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

struct ip_key
{
    __u8 family;
    __u8 pad[7];
    __u64 addr_lo;
    __u64 addr_hi;
};

struct counters
{
    __u64 bytes;
    __u64 packets;
};

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct ip_key);
    __type(value, struct counters);
} traffic_counters_ip SEC(".maps");

SEC("xdp")
int xdp_traffic_counter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 h_proto = eth->h_proto;
    __u64 pkt_len = data_end - data;

    if (h_proto == bpf_htons(ETH_P_IP))
    {
        struct iphdr *ip = data + sizeof(struct ethhdr);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        struct ip_key key = {};
        key.family = AF_INET;
        key.addr_lo = (__u64)ip->saddr; // IPv4 in low bits

        struct counters *c = bpf_map_lookup_elem(&traffic_counters_ip, &key);
        if (!c)
        {
            struct counters zero = {};
            bpf_map_update_elem(&traffic_counters_ip, &key, &zero, BPF_NOEXIST);
            c = bpf_map_lookup_elem(&traffic_counters_ip, &key);
            if (!c)
                return XDP_PASS;
        }

        __sync_fetch_and_add(&c->bytes, pkt_len);
        __sync_fetch_and_add(&c->packets, 1);
    }
    else if (h_proto == bpf_htons(ETH_P_IPV6))
    {
        struct ipv6hdr *ip6 = data + sizeof(struct ethhdr);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;

        struct ip_key key = {};
        key.family = AF_INET6;
        // store low/high 64-bits of IPv6 address
        __builtin_memcpy(&key.addr_lo, &ip6->saddr.s6_addr[0], 8);
        __builtin_memcpy(&key.addr_hi, &ip6->saddr.s6_addr[8], 8);

        struct counters *c = bpf_map_lookup_elem(&traffic_counters_ip, &key);
        if (!c)
        {
            struct counters zero = {};
            bpf_map_update_elem(&traffic_counters_ip, &key, &zero, BPF_NOEXIST);
            c = bpf_map_lookup_elem(&traffic_counters_ip, &key);
            if (!c)
                return XDP_PASS;
        }

        __sync_fetch_and_add(&c->bytes, pkt_len);
        __sync_fetch_and_add(&c->packets, 1);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "Dual BSD/GPL";
