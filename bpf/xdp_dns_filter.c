//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_dns_filter.h"

// AF_XDP Socket 映射
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_SOCKS);
} xsks_map SEC(".maps");

// 队列配置映射
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_SOCKS);
} qidconf_map SEC(".maps");

// DNS 端口过滤映射
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u8);
    __uint(max_entries, 64);
} dns_ports_map SEC(".maps");

// 指标统计映射 (per-CPU)
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct metrics);
    __uint(max_entries, 1);
} metrics_map SEC(".maps");

// IP 黑名单 (LPM Trie)
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(key_size, sizeof(struct lpm_key));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, 10000);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} ip_blacklist SEC(".maps");

// 更新统计指标
static __always_inline void update_metrics(struct metrics *m, int field) {
    if (!m) return;
    switch (field) {
        case 0: __sync_fetch_and_add(&m->total_packets, 1); break;
        case 1: __sync_fetch_and_add(&m->dns_packets, 1); break;
        case 2: __sync_fetch_and_add(&m->redirected, 1); break;
        case 3: __sync_fetch_and_add(&m->blocked, 1); break;
        case 4: __sync_fetch_and_add(&m->passed, 1); break;
    }
}

// 检查是否为 DNS 端口
static __always_inline int is_dns_port(__u16 port) {
    __u8 *val = bpf_map_lookup_elem(&dns_ports_map, &port);
    return val != NULL;
}

SEC("xdp")
int xdp_dns_filter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // 获取指标
    __u32 key = 0;
    struct metrics *m = bpf_map_lookup_elem(&metrics_map, &key);
    if (m) {
        update_metrics(m, 0); // total_packets
    }

    // 1. 解析以太网头
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // 只处理 IPv4/IPv6
    __u16 h_proto = bpf_ntohs(eth->h_proto);
    if (h_proto != ETH_P_IP && h_proto != ETH_P_IPV6)
        return XDP_PASS;

    // 2. 解析 IP 头
    struct iphdr *iph = NULL;
    struct ipv6hdr *ip6h = NULL;
    void *l4_hdr;
    __u8 protocol;

    if (h_proto == ETH_P_IP) {
        iph = (void *)(eth + 1);
        if ((void *)(iph + 1) > data_end)
            return XDP_PASS;
        protocol = iph->protocol;
        l4_hdr = (void *)iph + (iph->ihl * 4);
    } else {
        ip6h = (void *)(eth + 1);
        if ((void *)(ip6h + 1) > data_end)
            return XDP_PASS;
        protocol = ip6h->nexthdr;
        l4_hdr = (void *)(ip6h + 1);
    }

    // 3. 只处理 UDP
    if (protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udph = l4_hdr;
    if ((void *)(udph + 1) > data_end)
        return XDP_PASS;

    // 4. 检查是否为 DNS 端口
    __u16 dst_port = bpf_ntohs(udph->dest);
    __u16 src_port = bpf_ntohs(udph->source);

    if (!is_dns_port(dst_port) && !is_dns_port(src_port))
        return XDP_PASS;

    // 5. 验证 DNS 包结构
    struct dns_hdr *dnsh = (void *)(udph + 1);
    if ((void *)(dnsh + 1) > data_end)
        return XDP_PASS;

    // 更新 DNS 包计数
    if (m) {
        update_metrics(m, 1); // dns_packets
    }

    // 6. IP 黑名单检查 (IPv4 only)
    if (iph) {
        struct lpm_key lpm = { .prefixlen = 32, .addr = iph->saddr };
        if (bpf_map_lookup_elem(&ip_blacklist, &lpm)) {
            if (m) update_metrics(m, 3); // blocked
            return XDP_DROP;
        }
    }

    // 7. 重定向到 AF_XDP Socket
    int index = ctx->rx_queue_index;
    __u32 *qidconf = bpf_map_lookup_elem(&qidconf_map, &index);
    if (qidconf && *qidconf) {
        if (m) update_metrics(m, 2); // redirected
        return bpf_redirect_map(&xsks_map, index, XDP_PASS);
    }

    if (m) update_metrics(m, 4); // passed
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

