# 1. 创建网络环境
sudo ip netns add ns_test 2>/dev/null || true
sudo ip link add veth_xdp type veth peer name veth_send 2>/dev/null || true
sudo ip link set veth_send netns ns_test
sudo ip link set veth_xdp up
sudo ip addr add 10.99.0.1/24 dev veth_xdp 2>/dev/null || true
sudo ip netns exec ns_test ip link set lo up
sudo ip netns exec ns_test ip link set veth_send up
sudo ip netns exec ns_test ip addr add 10.99.0.2/24 dev veth_send 2>/dev/null || true

# 配置 ARP
echo 1 | sudo tee /proc/sys/net/ipv4/conf/veth_xdp/proxy_arp
MAC=$(ip link show veth_xdp | grep ether | awk '{print $2}')
sudo ip netns exec ns_test ip neigh replace 10.99.0.1 lladdr $MAC dev veth_send nud permanent

# 2. 创建配置文件
cat > /tmp/test_config.yaml << EOF
interface: veth_xdp
queue_id: 0
queue_count: 1
bpf_path: /home/lxx/work/xdp-dns/bpf/xdp_dns_filter_bpfel.o
rules_path: /home/lxx/work/xdp-dns/configs/rules.yaml
xdp:
  num_frames: 4096
  frame_size: 2048
  fill_ring_size: 2048
  comp_ring_size: 2048
  rx_ring_size: 2048
  tx_ring_size: 2048
workers:
  num_workers: 4
  batch_size: 64
dns:
  listen_ports:
    - 53
metrics:
  enabled: true
  listen: ":9095"
  path: "/metrics"
EOF

# 3. 启动 dns-filter
sudo /home/lxx/work/xdp-dns/build/dns-filter -config /tmp/test_config.yaml &

# 4. 等待启动后检查 maps
sleep 3
sudo bpftool map list
sudo bpftool map dump name qidconf_map
sudo bpftool map dump name dns_ports_map