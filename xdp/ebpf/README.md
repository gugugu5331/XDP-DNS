### env
```
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.23.3.linux-amd64.tar.gz 
export PATH=$PATH:/usr/local/go/bin
go version go1.23.2 linux/amd64
Linux Test 6.2.0-39-generic #40-Ubuntu SMP PREEMPT_DYNAMIC Tue Nov 14 14:18:00 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux

```
---
#### backup
```
# go env -w GOPROXY=https://mirrors.aliyun.com/goproxy/,direct
# go install github.com/cilium/ebpf@latest
# go install github.com/cilium/ebpf/cmd/bpf2go@latest

bpf2go install &
    GOPATH='/root/workspace/golang'
    /root/workspace/golang/bin/bpf2go
    
# export GOPACKAGE="ebpf"
# wget -qO - https://repo.iovisor.org/apt/Debian/gpg-key.asc | sudo apt-key add -
# echo "deb http://repo.iovisor.org/apt/Debian bionic main" | sudo tee /etc/apt/sources.list.d/iovisor.list
# apt-get update
# apt-get install -y clang llvm libelf-dev bpf-tools build-essential 
# apt-get install -y linux-headers-$(uname -r)

# /root/workspace/golang/bin/bpf2go ipproto single_protocol_filter.c -- -I/usr/include/ -I./include -nostdinc -O3
# /root/go/bin/bpf2go ipproto single_protocol_filter.c -- -I/usr/include/ -I./include -nostdinc -O3

# ip link set dev enp5s0f1 xdp off
# ethtool -l enp5s0f1
# ethtool -i enp5s0f1
# ethtool -x enp5s0f1
# ethtool -L enp5s0f1 combined 1
# cat /sys/class/net/enp5s0f1/queues/rx-0/rps_cpus
 000000
# cat /sys/class/net/enp5s0f1/queues/rx-1/rps_cpus

# echo 180 > /sys/class/net/enp5s0f1/queues/rx-0/rps_cpus
# echo 180 > /sys/class/net/enp5s0f1/queues/rx-1/rps_cpus
# ip link set enp5s0f1 down
# ip link set enp5s0f1 up
# systemctl stop irqbalance
# systemctl status irqbalance
# sh -c "echo 7-8 > /proc/irq/106/smp_affinity_list"
# sh -c "echo 7-8 > /proc/irq/107/smp_affinity_list"

# ip a | grep enp5s0f1
# go run dumpframes.go
# cat /proc/interrupts | grep enp5s0f1
# ip link show enp5s0f1
# ip link set dev enp5s0f1 xdp obj ipproto_bpfel.o sec xdp_sock queue_id 0
# ip link set dev enp5s0f1 xdp off

# cat /proc/net/if_inet6 


# ip addr add 127.0.0.100 dev lo
# ip addr del 127.0.0.100 dev lo

# ip addr add 3.3.3.5 dev enp5s0f1
# ip addr add 3.3.3.100 dev enp5s0f1
# ip addr add 3.3.3.101 dev enp5s0f1
# ip addr del 3.3.3.5 dev enp5s0f1
# ip addr del 3.3.3.100 dev enp5s0f1
# ip addr del 3.3.3.101 dev enp5s0f1

# cd /usr/include
# ln -s x86_64-linux-gnu/asm asm



c8i

cd server-api/tools/xdp/ebpf
export GOPACKAGE="ebpf"
/root/go/bin/bpf2go ipproto single_protocol_filter.c -- -I/usr/include/ -I./include -nostdinc -O3
bpftool prog load ipproto_bpfel.o /sys/fs/bpf/coredns_xdp type xdp
bpftool prog show
ip link show lo
ethtool -l eth0
ethtool -L eth0 combined 1
bpftool map show
bpftool map pin id 1 /sys/fs/bpf/coredns_qidconf_map
bpftool map pin id 3 /sys/fs/bpf/coredns_xsks_map
bpftool map pin id 4 /sys/fs/bpf/coredns_metrics_map
bpftool map pin id 5 /sys/fs/bpf/coredns_allow_port_map
bpftool map pin id 2 /sys/fs/bpf/coredns_queue_packets_map

bpftool map dump id 5
bpftool map dump id 1
bpftool map dump id 2
bpftool map dump id 4


bpftool map update id 5 key 187 1 0 0 value 1 0 0 0

bpftool net attach xdp id 93 dev eth0
bpftool net detach xdp dev lo

bpftool net attach xdpgeneric id 429 dev eth0
bpftool net -jp
bpftool net detach xdpgeneric dev eth0



# bpftool prog load ipproto_bpfel.o /sys/fs/bpf/coredns_xdp type xdp
# bpftool prog show
# bpftool net attach xdp id 1276 dev eth0
# bpftool net detach xdp dev eth0
# ip link show eth0
# bpftool map show
# bpftool map pin id 7 /sys/fs/bpf/coredns_qidconf_map
# bpftool map pin id 9 /sys/fs/bpf/coredns_xsks_map // 需要与go程序交互
# bpftool map pin id 10 /sys/fs/bpf/coredns_metrics_map
# bpftool map pin id 11 /sys/fs/bpf/coredns_allow_port_map
# bpftool map pin id 8 /sys/fs/bpf/coredns_queue_packets_map
# bpftool map dump id 892
# bpftool map dump id 893
# bpftool map dump id 894
# bpftool map dump id 7
# bpftool map lookup id 892 key 0 0 0 0
# bpftool map lookup id 892 key 1 0 0 0
# bpftool map lookup id 892 key 62 0 0 0
# bpftool map lookup id 892 key 63 0 0 0
# bpftool map update id 892 key 0 0 0 0 value 1 0 0 0
# bpftool map update id 892 key 1 0 0 0 value 1 0 0 0
# bpftool map update id 892 key 1 0 0 0 value 1 0 0 0

# bpftool map update id 894 key 53 0 0 0 value 1 0 0 0
# bpftool map update id 894 key 54 0 0 0 value 1 0 0 0
# bpftool map update id 894 key 55 0 0 0 value 1 0 0 0
#10053 bpftool map update id 11 key 69 39 0 0 value 1 0 0 0
#1053 bpftool map update id 265 key 29 4 0 0 value 1 0 0 0
#443 bpftool map update id 9 key 187 1 0 0 value 1 0 0 0
# bpftool map delete id 894 key 55 0 0 0

# rm -rf /sys/fs/bpf/*



cat /sys/kernel/debug/tracing/trace_pipe

bpf_printk("csum_l3_payload_section payload len: %u;", n);

char msg1[] = "reverse_qname q_name_len: %u\n";
bpf_trace_printk(msg1, sizeof(msg1), cache_key->q_name.prefixlen);
```


```
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 解析以太网头
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) return XDP_DROP;
    if (eth->h_proto != htons(ETH_P_IP)) return XDP_PASS;

    // 解析 IP 头
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end) return XDP_DROP;

    // 打印 IP 地址
    bpf_printk("IP src: %pI4, dst: %pI4", &ip->saddr, &ip->daddr);

    // 解析 TCP 头（如果是 TCP 包）
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)tcp + sizeof(*tcp) > data_end) return XDP_DROP;
        bpf_printk("TCP src_port: %d, dst_port: %d", 
                   ntohs(tcp->source), ntohs(tcp->dest));
    }

    return XDP_PASS;
}

```


```


bpftrace -e '
kprobe:tcp_v4_connect {
printf("TCP连接建立：进程 %s (PID: %d)\n",
comm, pid);
}
'


```