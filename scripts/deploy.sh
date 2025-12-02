#!/bin/bash
set -e

INSTALL_DIR="${INSTALL_DIR:-/opt/xdp-dns}"
SERVICE_NAME="xdp-dns-filter"
INTERFACE="${1:-eth0}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build"

echo "=== Deploying XDP DNS Filter ==="
echo "Install directory: ${INSTALL_DIR}"
echo "Interface: ${INTERFACE}"

# 检查 root 权限
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root"
    exit 1
fi

# 检查构建文件
if [ ! -f "${BUILD_DIR}/dns-filter" ]; then
    echo "Error: Build not found. Run 'scripts/build.sh' first."
    exit 1
fi

# 停止现有服务
if systemctl is-active --quiet ${SERVICE_NAME}; then
    echo "Stopping existing service..."
    systemctl stop ${SERVICE_NAME}
fi

# 创建安装目录
echo "Creating directories..."
mkdir -p ${INSTALL_DIR}/{bin,bpf,configs,logs}

# 复制文件
echo "Copying files..."
cp ${BUILD_DIR}/dns-filter ${INSTALL_DIR}/bin/
cp ${BUILD_DIR}/xdp_dns_filter_bpfel.o ${INSTALL_DIR}/bpf/ 2>/dev/null || true
cp -r ${BUILD_DIR}/configs/* ${INSTALL_DIR}/configs/ 2>/dev/null || true

# 更新配置文件中的接口名
sed -i "s/interface: .*/interface: ${INTERFACE}/" ${INSTALL_DIR}/configs/config.yaml 2>/dev/null || true

# 设置权限
chmod +x ${INSTALL_DIR}/bin/dns-filter

# 创建 systemd 服务
echo "Creating systemd service..."
cat > /etc/systemd/system/${SERVICE_NAME}.service << EOF
[Unit]
Description=XDP DNS Filter Service
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/bin/dns-filter -config ${INSTALL_DIR}/configs/config.yaml
ExecStop=/bin/kill -SIGTERM \$MAINPID
Restart=on-failure
RestartSec=5
LimitMEMLOCK=infinity
LimitNOFILE=65535

# 能力设置
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_BPF
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_ADMIN CAP_BPF

# 环境变量
Environment=GOGC=100

# 日志
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# 重新加载 systemd
systemctl daemon-reload

# 设置内存锁定限制
echo "Setting memory limits..."
if ! grep -q "xdp-dns" /etc/security/limits.d/99-xdp.conf 2>/dev/null; then
    cat > /etc/security/limits.d/99-xdp.conf << EOF
# XDP DNS Filter memory limits
* soft memlock unlimited
* hard memlock unlimited
EOF
fi

echo ""
echo "=== Deployment complete ==="
echo ""
echo "Commands:"
echo "  Start service:   systemctl start ${SERVICE_NAME}"
echo "  Stop service:    systemctl stop ${SERVICE_NAME}"
echo "  Enable service:  systemctl enable ${SERVICE_NAME}"
echo "  View logs:       journalctl -u ${SERVICE_NAME} -f"
echo "  Check status:    systemctl status ${SERVICE_NAME}"
echo ""
echo "Configuration: ${INSTALL_DIR}/configs/config.yaml"
echo "Rules:         ${INSTALL_DIR}/configs/rules.yaml"

