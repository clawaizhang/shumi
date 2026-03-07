#!/bin/bash
#
# 枢密 (Shumi) 一键安装脚本
# 自动安装并集成到 OpenClaw
#

set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 配置
SHUMI_VERSION="0.2.0"
PYTHON_MIN_VERSION="3.10"
INSTALL_DIR="${HOME}/.shumi"
CONFIG_DIR="${HOME}/.openclaw"

# 使用国内镜像加速
export HF_ENDPOINT=https://hf-mirror.com

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}  枢密 (Shumi) 一键安装脚本${NC}"
echo -e "${GREEN}================================${NC}"
echo ""

# ============================================
# 步骤1: 检查环境
# ============================================
echo -e "${YELLOW}[1/6] 检查环境...${NC}"

# 检查Python版本
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}错误: 未找到 Python3${NC}"
    echo "请安装 Python 3.10 或更高版本"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
REQUIRED_VERSION="3.10"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then 
    echo -e "${RED}错误: Python版本 $PYTHON_VERSION 过低${NC}"
    echo "需要 Python $PYTHON_MIN_VERSION 或更高版本"
    exit 1
fi

echo "  ✓ Python版本: $PYTHON_VERSION"

# 检查pip
if ! command -v pip3 &> /dev/null; then
    echo -e "${RED}错误: 未找到 pip3${NC}"
    exit 1
fi
echo "  ✓ pip3 已安装"

# 检查git
if ! command -v git &> /dev/null; then
    echo -e "${RED}错误: 未找到 git${NC}"
    exit 1
fi
echo "  ✓ git 已安装"

echo ""

# ============================================
# 步骤2: 安装依赖包
# ============================================
echo -e "${YELLOW}[2/6] 安装Python依赖...${NC}"

# 安装sentence-transformers（国内镜像）
echo "  安装 sentence-transformers..."
pip3 install sentence-transformers --quiet --break-system-packages 2>/dev/null || pip3 install sentence-transformers --quiet 2>/dev/null || {
    echo "  警告: pip安装失败，尝试使用apt..."
    apt-get update -qq && apt-get install -y -qq python3-sentence-transformers 2>/dev/null || true
}

echo "  ✓ 依赖安装完成"
echo ""

# ============================================
# 步骤3: 下载Embedding模型
# ============================================
echo -e "${YELLOW}[3/6] 下载AI模型 (all-MiniLM-L6-v2)...${NC}"
echo "  模型大小约90MB，使用国内镜像加速..."
echo "  如果下载慢，可以按Ctrl+C跳过，稍后手动下载"

python3 << 'EOF'
import os
os.environ['HF_ENDPOINT'] = 'https://hf-mirror.com'

from sentence_transformers import SentenceTransformer
import sys

try:
    print("  正在下载/加载模型...")
    model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')
    print("  ✓ 模型准备就绪")
except Exception as e:
    print(f"  警告: 模型下载失败: {e}", file=sys.stderr)
    print("  您可以稍后手动运行: python3 -c \"from sentence_transformers import SentenceTransformer; SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')\"")
    sys.exit(0)  # 不中断安装
EOF

echo ""

# ============================================
# 步骤4: 安装枢密包
# ============================================
echo -e "${YELLOW}[4/6] 安装枢密 (Shumi)...${NC}"

# 克隆仓库
if [ -d "$INSTALL_DIR" ]; then
    echo "  更新现有安装..."
    cd "$INSTALL_DIR"
    git pull origin main
else
    echo "  克隆仓库..."
    git clone https://github.com/clawaizhang/shumi.git "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

# 安装枢密包
echo "  安装枢密包..."
pip3 install -e . --quiet --break-system-packages 2>/dev/null || pip3 install -e . --quiet 2>/dev/null

echo "  ✓ 枢密安装完成"
echo ""

# ============================================
# 步骤5: 初始化配置
# ============================================
echo -e "${YELLOW}[5/6] 初始化配置...${NC}"

# 创建配置目录
mkdir -p "$CONFIG_DIR"
mkdir -p "$HOME/.shumi/security"
mkdir -p "$HOME/.shumi/logs"

echo "  ✓ 配置目录已创建"

# 生成SSH密钥对（如果不存在）
if [ ! -f "$HOME/.ssh/id_rsa" ]; then
    echo "  生成SSH密钥对..."
    mkdir -p "$HOME/.ssh"
    ssh-keygen -t rsa -b 4096 -f "$HOME/.ssh/id_rsa" -N "" -C "shumi@$(hostname)" >/dev/null 2>&1
    chmod 600 "$HOME/.ssh/id_rsa"
    chmod 644 "$HOME/.ssh/id_rsa.pub"
    echo "  ✓ 密钥对已生成"
else
    echo "  ✓ 使用现有SSH密钥"
fi

echo ""

# ============================================
# 步骤6: 集成OpenClaw
# ============================================
echo -e "${YELLOW}[6/6] 集成到OpenClaw...${NC}"

CONFIG_FILE="$CONFIG_DIR/config.yaml"

# 备份现有配置
if [ -f "$CONFIG_FILE" ]; then
    cp "$CONFIG_FILE" "$CONFIG_FILE.backup.$(date +%Y%m%d%H%M%S)"
    echo "  ✓ 已备份现有配置"
fi

# 创建或更新配置
cat > "$CONFIG_FILE" <> 'EOF'
# OpenClaw 配置文件
# 枢密 (Shumi) 自动集成

preprocessors:
  - shumi.plugins.openclaw_hook:SecurityAuditHook

postprocessors:
  - shumi.plugins.openclaw_hook:SecurityAuditHook

# 枢密配置
shumi:
  notification_level: brief  # silent | brief | detailed

logging:
  level: INFO
  format: "%(asctime)s - %(name)s - %(message)s"
EOF

echo "  ✓ OpenClaw配置已更新"
echo ""

# ============================================
# 验证安装
# ============================================
echo -e "${YELLOW}[验证] 测试安装...${NC}"

python3 << 'EOF'
import sys
import os
os.environ['HF_ENDPOINT'] = 'https://hf-mirror.com'

try:
    from shumi.core.notifier import ShumiNotifier
    import logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(message)s')
    
    notifier = ShumiNotifier(level='brief')
    notifier.on_encryption(1, ['test'])
    
    print("✓ 枢密模块测试通过")
    
except Exception as e:
    print(f"✗ 测试失败: {e}", file=sys.stderr)
    sys.exit(1)
EOF

if [ $? -eq 0 ]; then
    echo "  ✓ 安装验证通过"
else
    echo -e "${RED}  ✗ 安装验证失败${NC}"
    exit 1
fi

echo ""

# ============================================
# 安装完成
# ============================================
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}  安装完成！${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo "使用说明:"
echo "  1. 枢密已自动集成到OpenClaw"
echo "  2. 发送给AI的消息会自动检测并加密敏感信息"
echo "  3. AI响应中的占位符会自动解密"
echo ""
echo "配置文件: $CONFIG_FILE"
echo "日志位置: ~/.shumi/logs/"
echo "模型缓存: ~/.cache/huggingface/"
echo ""
echo "通知级别设置:"
echo "  - silent: 完全静默"
echo "  - brief: 简略通知（默认）"
echo "  - detailed: 详细通知"
echo ""
echo "测试命令:"
echo "  python3 -c \"from shumi.core.notifier import ShumiNotifier; n=ShumiNotifier('detailed'); n.on_encryption(1,['api_key'])\""
echo ""
