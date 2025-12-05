#!/usr/bin/env bash
#
# xdp_dns_qps_v2_fixed.sh
# 修复版：解决 v2 版本的 jq 路径错误和性能问题
#
# 用法：
#   sudo ./xdp_dns_qps_v2_fixed.sh [间隔秒] [metrics_map_id]
#
# 示例：
#   # 间隔 1 秒，使用 name=metrics_map
#   sudo ./xdp_dns_qps_v2_fixed.sh
#
#   # 间隔 2 秒，指定 metrics_map 的 id=505
#   sudo ./xdp_dns_qps_v2_fixed.sh 2 505

set -euo pipefail

INTERVAL="${1:-1}"
MAP_ID="${2:-}"

# 依赖检查
for bin in bpftool jq curl awk; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "缺少依赖: $bin" >&2
    exit 1
  fi
done

# 读取 metrics_map 原始 JSON（缓存使用）
get_metrics_json() {
  if [[ -n "$MAP_ID" ]]; then
    sudo bpftool -j map dump id "$MAP_ID" 2>/dev/null || return 1
  else
    sudo bpftool -j map dump name metrics_map 2>/dev/null || return 1
  fi
}

# XDP 层：所有 CPU 的 dns_packets 求和（使用 formatted 字段）
get_xdp_dns_packets() {
  local json="$1"
  echo "$json" | jq -r '
    if (. | length == 0) then 0
    else [.[0].formatted.values[]?.value.dns_packets // 0] | add // 0
    end
  '
}

# 打印有流量的 CPU（total_packets > 0）- 简化版
show_hot_cpus() {
  local json="$1"
  echo "$json" | jq -r '
    [.[0].formatted.values[]? | select(.value.total_packets > 0)]
    | "  活跃CPU数: \(length), 总包数: \([.[].value.total_packets] | add // 0)"
  '
}

# 用户态：/stats 里的 received
get_user_received() {
  curl -s http://127.0.0.1:9090/stats 2>/dev/null \
    | jq -r '.received // 0'
}

# 优雅退出
trap 'echo ""; echo "# Stopped at $(date)"; exit 0' SIGINT SIGTERM

# 第一次读取
echo "# 初始化..."
metrics_json=$(get_metrics_json) || {
  echo "错误: 无法读取 metrics_map" >&2
  exit 1
}

xdp_prev=$(get_xdp_dns_packets "$metrics_json")
usr_prev=$(get_user_received)

if [[ -z "$xdp_prev" || -z "$usr_prev" || "$xdp_prev" == "null" || "$usr_prev" == "null" ]]; then
  echo "初始化失败，请确认 metrics_map 和 /stats 正常 (xdp=$xdp_prev, usr=$usr_prev)" >&2
  exit 1
fi

echo "# interval=${INTERVAL}s map=${MAP_ID:-metrics_map(name)}"
printf "# %-19s | %10s %10s | %12s %12s\n" \
  "time" "XDP_QPS" "USR_QPS" "ΔXDP_DNS" "ΔUSR_RECV"
echo "#-------------------------------------------------------------"

while true; do
  sleep "$INTERVAL"

  # 只调用一次 bpftool，重复使用结果
  metrics_json=$(get_metrics_json) || {
    echo "$(date '+%F %T')  警告: 无法读取 metrics_map" >&2
    continue
  }

  xdp_now=$(get_xdp_dns_packets "$metrics_json")
  usr_now=$(get_user_received)

  if [[ -z "$xdp_now" || -z "$usr_now" || "$xdp_now" == "null" || "$usr_now" == "null" ]]; then
    echo "$(date '+%F %T')  警告: metrics 无效 (xdp=$xdp_now, usr=$usr_now)" >&2
    continue
  fi

  # 用 awk 做减法和 QPS 计算（四舍五入）
  dx=$(awk -v a="$xdp_now" -v b="$xdp_prev" 'BEGIN{
      d = a - b;
      if (d < 0) d = 0;
      print d;
  }')

  du=$(awk -v a="$usr_now" -v b="$usr_prev" 'BEGIN{
      d = a - b;
      if (d < 0) d = 0;
      print d;
  }')

  # 计算整数 QPS（四舍五入）
  xdp_qps=$(awk -v d="$dx" -v T="$INTERVAL" 'BEGIN{
      if (T <= 0) T = 1;
      print int(d / T + 0.5);
  }')

  usr_qps=$(awk -v d="$du" -v T="$INTERVAL" 'BEGIN{
      if (T <= 0) T = 1;
      print int(d / T + 0.5);
  }')

  printf "%-20s | %10d %10d | %12d %12d\n" \
    "$(date '+%F %T')" \
    "$xdp_qps" "$usr_qps" "$dx" "$du"

  show_hot_cpus "$metrics_json"
  echo

  xdp_prev="$xdp_now"
  usr_prev="$usr_now"
done

