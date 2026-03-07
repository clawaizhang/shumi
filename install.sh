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
# 步骤2: 安装枢密包
# ============================================
echo -e "${YELLOW}[2/6] 安装枢密 (Shumi)...${NC}"

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

# 安装依赖
echo "  安装依赖..."
pip3 install -e . --quiet

echo "  ✓ 枢密安装完成"
echo ""

# ============================================
# 步骤3: 下载Embedding模型
# ============================================
echo -e "${YELLOW}[3/6] 下载AI模型 (all-MiniLM-L6-v2)...${NC}"
echo "  模型大小约90MB，首次下载可能需要几分钟..."

python3 << 'EOF'
from sentence_transformers import SentenceTransformer
import sys

try:
    print("  正在下载模型...")
    model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')
    print("  ✓ 模型下载完成")
except Exception as e:
    print(f"  下载失败: {e}", file=sys.stderr)
    sys.exit(1)
EOF

echo ""

# ============================================
# 步骤4: 初始化配置
# ============================================
echo -e "${YELLOW}[4/6] 初始化配置...${NC}"

# 创建配置目录
mkdir -p "$CONFIG_DIR"
mkdir -p "$HOME/.shumi/security"

echo "  ✓ 配置目录已创建"

# 生成SSH密钥对（如果不存在）
if [ ! -f "$HOME/.ssh/id_rsa" ]; then
    echo "  生成SSH密钥对..."
    ssh-keygen -t rsa -b 4096 -f "$HOME/.ssh/id_rsa" -N "" -C "shumi@$(hostname)"
    echo "  ✓ 密钥对已生成"
else
    echo "  ✓ 使用现有SSH密钥"
fi

echo ""

# ============================================
# 步骤5: 集成OpenClaw
# ============================================
echo -e "${YELLOW}[5/6] 集成到OpenClaw...${NC}"

CONFIG_FILE="$CONFIG_DIR/config.yaml"

# 备份现有配置
if [ -f "$CONFIG_FILE" ]; then
    cp "$CONFIG_FILE" "$CONFIG_FILE.backup.$(date +%Y%m%d%H%M%S)"
    echo "  ✓ 已备份现有配置"
fi

# 创建或更新配置
cat > "$CONFIG_FILE" << 'EOF'
# OpenClaw 配置文件
# 枢密 (Shumi) 自动集成

preprocessors:
  - shumi.plugins.openclaw_hook:SecurityAuditHook

postprocessors:
  - shumi.plugins.openclaw_hook:SecurityAuditHook

# 枢密配置
shumi:
  notification_level: brief  # silent | brief | detailed
  chunk_strategy_path: ~/.shumi/data/chunk_strategy.json

logging:
  level: INFO
  format: "%(asctime)s - %(name)s - %(message)s"
EOF

echo "  ✓ OpenClaw配置已更新"
echo ""

# ============================================
# 步骤6: 验证安装
# ============================================
echo -e "${YELLOW}[6/6] 验证安装...${NC}"

python3 << 'EOF'
import sys
try:
    import shumi
    from shumi.core.ai_detector import AISensitiveDetector
    from shumi.core.notifier import ShumiNotifier
    print("  ✓ 枢密包导入成功")
    print(f"  ✓ 版本: {shumi.__version__}")
except ImportError as e:
    print(f"  ✗ 导入失败: {e}", file=sys.stderr)
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
echo ""
echo "测试命令:"
echo "  shumi detect \"我的API Key是 sk-test123\""
echo ""
