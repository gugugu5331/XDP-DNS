// +build ignore

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


#define MAX_SOCKS 4
#define MAX_METRICS 4

static volatile unsigned const short PORT;
static volatile unsigned const short PORT = 53;

//Ensure map references are available.
/*
        These will be initiated from go and
        referenced in the end BPF opcodes by file descriptor
*/

/*
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
	unsigned int map_flags;
};

struct bpf_map_def SEC("maps") xsks_map = {
	.type = BPF_MAP_TYPE_XSKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = MAX_SOCKS,
};

struct bpf_map_def SEC("maps") qidconf_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = MAX_SOCKS,
};
*/

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_SOCKS);
} xsks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_SOCKS);
} qidconf_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_SOCKS);
} queue_packets_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_METRICS);
} metrics_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_METRICS);
} allow_port_map SEC(".maps");


SEC("xdp_sock") int xdp_sock_prog(struct xdp_md *ctx)
{

	int index = ctx->rx_queue_index;
	// A set entry here means that the correspnding queue_id
	// has an active AF_XDP socket bound to it.
	if (bpf_map_lookup_elem(&qidconf_map, &index))
	{
		// redirect packets to an xdp socket that match the given IPv4 or IPv6 protocol; pass all other packets to the kernel
		void *data = (void *)(long)ctx->data;
		void *data_end = (void *)(long)ctx->data_end;
		struct ethhdr *eth = data;
		__u16 h_proto = eth->h_proto;
		if ((void *)eth + sizeof(*eth) > data_end)
			return XDP_PASS;

		if (bpf_htons(h_proto) != ETH_P_IP)
			return XDP_PASS;

		struct iphdr *ip = data + sizeof(*eth);
		if ((void *)ip + sizeof(*ip) > data_end)
			return XDP_PASS;

        // uoa must be udp packet
        if (ip->protocol == 248){
            int *value2;
            value2 = bpf_map_lookup_elem(&queue_packets_map, &index);
            if (value2) {
                __sync_fetch_and_add(value2, 1);
            }
        	return bpf_redirect_map(&xsks_map, index, 0);
        }
		// Only UDP
		if (ip->protocol != IPPROTO_UDP)
			return XDP_PASS;

		struct udphdr *udp = (void *)ip + sizeof(*ip);
		if ((void *)udp + sizeof(*udp) > data_end)
			return XDP_PASS;

        // if (udp->dest == bpf_htons(PORT)) { }
        int key = 0;
        int *value;
        value = bpf_map_lookup_elem(&metrics_map, &key);
        if (value) {
            __sync_fetch_and_add(value, 1);
        }

        short dp = bpf_ntohs(udp->dest);
        if (bpf_map_lookup_elem(&allow_port_map, &dp)) {
           int key1 = 1;
           int *value1;
           value1 = bpf_map_lookup_elem(&metrics_map, &key1);
           if (value1) {
               __sync_fetch_and_add(value1, 1);
           }

           int *value2;
           value2 = bpf_map_lookup_elem(&queue_packets_map, &index);
           if (value2) {
               __sync_fetch_and_add(value2, 1);
           }
		   return bpf_redirect_map(&xsks_map, index, 0);
		}
	}
	return XDP_PASS;
}

// Basic license just for compiling the object code
char __license[] SEC("license") = "GPL";