#!/bin/bash
# AI安全审计插件安装脚本 - 兵部负责
# 用法: ./install.sh [选项]

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 默认配置
INSTALL_USER_MODE=false
SKIP_DEPS=false
CONFIG_DIR="$HOME/.openclaw/security"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}  AI安全审计插件安装程序${NC}"
echo -e "${BLUE}========================================${NC}"
echo

# 解析参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --user)
            INSTALL_USER_MODE=true
            shift
            ;;
        --skip-deps)
            SKIP_DEPS=true
            shift
            ;;
        --help)
            echo "用法: ./install.sh [选项]"
            echo
            echo "选项:"
            echo "  --user       用户模式安装（不依赖系统Python）"
            echo "  --skip-deps  跳过依赖检查"
            echo "  --help       显示此帮助信息"
            exit 0
            ;;
        *)
            echo -e "${RED}错误: 未知选项 $1${NC}"
            exit 1
            ;;
    esac
done

# 检查Python版本
echo -e "${BLUE}[1/6] 检查Python环境...${NC}"
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}错误: 未找到 Python3${NC}"
    echo "请先安装 Python 3.10 或更高版本"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | grep -oP '\d+\.\d+')
REQUIRED_VERSION="3.10"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$PYTHON_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo -e "${RED}错误: Python版本 $PYTHON_VERSION 过低${NC}"
    echo "需要 Python $REQUIRED_VERSION 或更高版本"
    exit 1
fi

echo -e "${GREEN}✓${NC} Python版本: $PYTHON_VERSION"

# 检查pip
echo -e "${BLUE}[2/6] 检查pip...${NC}"
if ! command -v pip3 &> /dev/null; then
    echo -e "${YELLOW}警告: 未找到 pip3，尝试安装...${NC}"
    python3 -m ensurepip --upgrade
fi
echo -e "${GREEN}✓${NC} pip已安装"

# 检查SSH密钥
echo -e "${BLUE}[3/6] 检查SSH密钥...${NC}"
SSH_DIR="$HOME/.ssh"
PUB_KEY_FOUND=false

for key_file in "$SSH_DIR/id_rsa.pub" "$SSH_DIR/id_ed25519.pub"; do
    if [ -f "$key_file" ]; then
        echo -e "${GREEN}✓${NC} 发现公钥: $key_file"
        PUB_KEY_FOUND=true
        break
    fi
done

if [ "$PUB_KEY_FOUND" = false ]; then
    echo -e "${YELLOW}警告: 未找到SSH公钥${NC}"
    echo "建议生成SSH密钥对用于加密:"
    echo "  ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa"
    echo
    read -p "是否继续安装? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# 安装依赖
echo -e "${BLUE}[4/6] 安装依赖...${NC}"
if [ "$SKIP_DEPS" = false ]; then
    pip3 install --upgrade pip
    if [ "$INSTALL_USER_MODE" = true ]; then
        pip3 install --user -e "."
    else
        pip3 install -e "."
    fi
    echo -e "${GREEN}✓${NC} 依赖安装完成"
else
    echo -e "${YELLOW}!${NC} 跳过依赖安装"
fi

# 创建配置目录
echo -e "${BLUE}[5/6] 创建配置目录...${NC}"
mkdir -p "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

# 复制默认配置（如果不存在）
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    if [ -f "config/default.yaml" ]; then
        cp config/default.yaml "$CONFIG_DIR/config.yaml"
        chmod 600 "$CONFIG_DIR/config.yaml"
        echo -e "${GREEN}✓${NC} 配置文件已创建: $CONFIG_DIR/config.yaml"
    fi
else
    echo -e "${YELLOW}!${NC} 配置文件已存在，跳过"
fi

# 复制SSH公钥到配置目录
if [ "$PUB_KEY_FOUND" = true ]; then
    for key_file in "$SSH_DIR/id_rsa.pub" "$SSH_DIR/id_ed25519.pub"; do
        if [ -f "$key_file" ]; then
            cp "$key_file" "$CONFIG_DIR/id_rsa.pub"
            chmod 644 "$CONFIG_DIR/id_rsa.pub"
            echo -e "${GREEN}✓${NC} 公钥已复制到配置目录"
            break
        fi
    done
fi

echo -e "${GREEN}✓${NC} 配置目录已创建: $CONFIG_DIR"

# 配置OpenClaw集成
echo -e "${BLUE}[6/6] 配置OpenClaw集成...${NC}"
OPENCLAW_CONFIG="$HOME/.openclaw/config.yaml"

if [ -f "$OPENCLAW_CONFIG" ]; then
    # 检查是否已配置
    if grep -q "ai_security_audit" "$OPENCLAW_CONFIG"; then
        echo -e "${YELLOW}!${NC} OpenClaw配置中已存在安全审计插件"
    else
        echo "请手动在 $OPENCLAW_CONFIG 中添加:"
        echo
        echo "preprocessors:"
        echo "  - ai_security_audit.plugins.openclaw_hook:SecurityAuditHook"
        echo
    fi
else
    echo -e "${YELLOW}!${NC} 未找到OpenClaw配置文件"
    echo "安装完成后，请在 ~/.openclaw/config.yaml 中添加:"
    echo
    echo "preprocessors:"
    echo "  - ai_security_audit.plugins.openclaw_hook:SecurityAuditHook"
    echo
fi

echo -e "${GREEN}✓${NC} 安装完成!"
echo
echo -e "${BLUE}========================================${NC}"
echo -e "${GREEN}  AI安全审计插件安装成功!${NC}"
echo -e "${BLUE}========================================${NC}"
echo
echo "使用说明:"
echo "  ai-security --help          显示帮助信息"
echo "  ai-security config show     查看当前配置"
echo "  ai-security scan <file>     扫描文件中的敏感信息"
echo "  ai-security decrypt <placeholder>  解密占位符"
echo "  ai-security audit logs      查看审计日志"
echo
echo "如需帮助，请查看文档: docs/guide.md"
echo
