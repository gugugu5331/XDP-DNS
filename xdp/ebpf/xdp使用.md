# 1. 第一步 根据c文件生成大小端的文件
 ```
    export GOPACKAGE="ebpf" && /root/go/bin/bpf2go ipproto single_protocol_filter.c -- -I/usr/include/ -I./include -nostdinc -O3
 ```
# 2. 我们一般把大端程序加载到内核上面
 ```
    bpftool prog load ipproto_bpfel.o /sys/fs/bpf/mon_xdp type xdp
 ```
# 3. 查看挂在内核程序上的id 和文件
  ## 3.1 查看下面的文件
   ``` ll /sys/fs/bpf/  ```
  ## 3.2  查看加载程序的id
   ``` bpftool prog show ```
# 4. 根据加载程序的id attach 对应的网卡上
  ``` bpftool net attach xdp id xxx dev eth0 ```
  ### 查看是否 attach 成功
   ``` ip link show eth0  ```
# 5.根据 bpftool map show 命令 找的名字 为 xsks_map 的id 把他pin 上去，这样用户态可以用
 ```
    bpftool map pin id xxx /sys/fs/bpf/mon_xsks_map
```
# 6.最后开放端口 bpftool map show 命令 找的名字 为 allow_port_map 的id 修改里面的值,并查看map 值
```
    bpftool map update id 147 key 69 39 0 0 value 1 0 0 0
    bpftool map dump id xxx
```