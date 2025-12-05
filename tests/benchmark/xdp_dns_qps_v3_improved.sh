#!/usr/bin/env bash
#
# xdp_dns_qps_v3_improved.sh
# 优化版：统计 XDP 和用户态的 QPS，解决 v2 版本的问题
#
# 用法：
#   sudo ./xdp_dns_qps_v3_improved.sh [间隔秒] [metrics_map_id] [--show-cpus]
#
# 示例：
#   # 间隔 1 秒，使用 name=metrics_map
#   sudo ./xdp_dns_qps_v3_improved.sh
#
#   # 间隔 2 秒，指定 metrics_map 的 id=505，显示 CPU 详情
#   sudo ./xdp_dns_qps_v3_improved.sh 2 505 --show-cpus

set -euo pipefail

INTERVAL="${1:-1}"
MAP_ID="${2:-}"
SHOW_CPUS=false
USER_PORT="${USER_PORT:-9090}"

# 解析参数
for arg in "$@"; do
  if [[ "$arg" == "--show-cpus" ]]; then
    SHOW_CPUS=true
  fi
done

# 依赖检查
for bin in bpftool jq curl awk date; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "Error: Missing dependency: $bin" >&2
    exit 1
  fi
done

# 读取 metrics_map 原始 JSON（只调用一次，缓存使用）
get_metrics_json() {
  local json
  if [[ -n "$MAP_ID" ]]; then
    json=$(sudo bpftool -j map dump id "$MAP_ID" 2>/dev/null) || return 1
  else
    json=$(sudo bpftool -j map dump name metrics_map 2>/dev/null) || return 1
  fi
  echo "$json"
}

# XDP 层：所有 CPU 的 dns_packets 求和
get_xdp_dns_packets() {
  local json="$1"
  echo "$json" | jq -r '
    if (. | length == 0) then 0
    else [.[0].formatted.values[]?.value.dns_packets // 0] | add // 0
    end
  '
}

# 用户态：/stats 里的 received
get_user_received() {
  curl -s "http://127.0.0.1:${USER_PORT}/stats" 2>/dev/null \
    | jq -r '.received // 0'
}

# 获取有流量的 CPU 数量和总包数
get_hot_cpu_summary() {
  local json="$1"
  echo "$json" | jq -r '
    [.[0].formatted.values[]? | select(.value.total_packets > 0)]
    | "CPUs:\(length) Total:\([.[].value.total_packets] | add // 0)"
  '
}

# 打印有流量的 CPU 详情（简化版）
show_hot_cpus() {
  local json="$1"
  echo "$json" | jq -r '
    .[0].formatted.values[]?
    | select(.value.total_packets > 0)
    | "  CPU\(.cpu): total=\(.value.total_packets) dns=\(.value.dns_packets) dropped=\(.value.blocked)"
  '
}

# 优雅退出处理
cleanup() {
  echo ""
  echo "# Monitoring stopped at $(date '+%F %T')"
  exit 0
}
trap cleanup SIGINT SIGTERM

# 获取纳秒时间戳（用于精确计时）
get_nanos() {
  date +%s%N
}

# 初始化
echo "# Initializing..."
metrics_json=$(get_metrics_json) || {
  echo "Error: Failed to read metrics_map (name: metrics_map, id: ${MAP_ID:-auto})" >&2
  exit 1
}

xdp_prev=$(get_xdp_dns_packets "$metrics_json")
usr_prev=$(get_user_received)
time_prev=$(get_nanos)

if [[ -z "$xdp_prev" || -z "$usr_prev" || "$xdp_prev" == "null" || "$usr_prev" == "null" ]]; then
  echo "Error: Failed to initialize counters (xdp=$xdp_prev, usr=$usr_prev)" >&2
  exit 1
fi

echo "# interval=${INTERVAL}s map=${MAP_ID:-metrics_map(name)} port=${USER_PORT}"
printf "# %-19s | %12s %12s | %12s %12s | %s\n" \
  "time" "XDP_QPS" "USR_QPS" "ΔXDP" "ΔUSR" "HOT_CPUS"
echo "#---------------------------------------------------------------------------------"

iteration=0
while true; do
  sleep "$INTERVAL"
  
  ((iteration++))
  time_now=$(get_nanos)
  
  # 只调用一次 bpftool，缓存使用
  metrics_json=$(get_metrics_json) || {
    echo "$(date '+%F %T')  Warning: Failed to read metrics_map" >&2
    continue
  }

  xdp_now=$(get_xdp_dns_packets "$metrics_json")
  usr_now=$(get_user_received)

  if [[ -z "$xdp_now" || -z "$usr_now" || "$xdp_now" == "null" || "$usr_now" == "null" ]]; then
    echo "$(date '+%F %T')  Warning: Invalid metrics (xdp=$xdp_now, usr=$usr_now)" >&2
    continue
  fi

  # 计算实际时间间隔（秒，保留小数）
  actual_interval=$(awk -v now="$time_now" -v prev="$time_prev" 'BEGIN{
    printf "%.3f", (now - prev) / 1e9
  }')

  # 计算增量和 QPS（四舍五入）
  read dx xdp_qps < <(awk -v now="$xdp_now" -v prev="$xdp_prev" -v T="$actual_interval" 'BEGIN{
    d = now - prev;
    if (d < 0) d = 0;
    qps = (T > 0) ? int(d / T + 0.5) : 0;
    printf "%d %d", d, qps;
  }')

  read du usr_qps < <(awk -v now="$usr_now" -v prev="$usr_prev" -v T="$actual_interval" 'BEGIN{
    d = now - prev;
    if (d < 0) d = 0;
    qps = (T > 0) ? int(d / T + 0.5) : 0;
    printf "%d %d", d, qps;
  }')

  hot_cpu_summary=$(get_hot_cpu_summary "$metrics_json")

  printf "%-20s | %12d %12d | %12d %12d | %s\n" \
    "$(date '+%F %T')" \
    "$xdp_qps" "$usr_qps" "$dx" "$du" \
    "$hot_cpu_summary"

  # 可选：每 10 次迭代或用户指定时显示详细 CPU 信息
  if [[ "$SHOW_CPUS" == true ]] && ((iteration % 10 == 0)); then
    echo "  ---- CPU Details ----"
    show_hot_cpus "$metrics_json"
    echo
  fi

  xdp_prev="$xdp_now"
  usr_prev="$usr_now"
  time_prev="$time_now"
done

