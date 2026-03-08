#!/bin/bash
#
# 枢密 (Shumi) 一键安装脚本 - Release版
# 从GitHub Release下载预编译模型
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

INSTALL_DIR="${HOME}/.shumi"
MODEL_URL="https://github.com/clawaizhang/shumi/releases/download/v0.3.0-onnx/model.onnx"
MODEL_DATA_URL="https://github.com/clawaizhang/shumi/releases/download/v0.3.0-onnx/model.onnx.data"

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}  枢密 (Shumi) 一键安装${NC}"
echo -e "${GREEN}  ONNX快速版${NC}"
echo -e "${GREEN}================================${NC}"
echo ""

# 检查环境
echo -e "${YELLOW}[1/5] 检查环境...${NC}"
python3 --version >/dev/null 2>&1 || { echo -e "${RED}错误: 需要Python 3.10+${NC}"; exit 1; }
echo "  ✓ Python OK"

# 安装依赖
echo -e "${YELLOW}[2/5] 安装ONNX依赖...${NC}"
pip3 install onnxruntime transformers --quiet --break-system-packages 2>/dev/null || \
pip3 install onnxruntime transformers --quiet 2>/dev/null
echo "  ✓ 依赖安装完成"

# 克隆仓库（包含tokenizer文件）
echo -e "${YELLOW}[3/5] 下载枢密代码...${NC}"
if [ -d "$INSTALL_DIR/.git" ]; then
    cd "$INSTALL_DIR" && git pull origin main --quiet
    echo "  ✓ 代码已更新"
else
    rm -rf "$INSTALL_DIR"
    git clone https://github.com/clawaizhang/shumi.git "$INSTALL_DIR" --quiet
    echo "  ✓ 代码下载完成"
fi

# 下载模型文件（如果没有）
echo -e "${YELLOW}[4/5] 检查模型文件...${NC}"
mkdir -p "${INSTALL_DIR}/models"

if [ -f "${INSTALL_DIR}/models/model.onnx" ] && [ -f "${INSTALL_DIR}/models/model.onnx.data" ]; then
    echo "  ✓ 模型文件已存在，跳过下载"
else
    echo "  从GitHub Release下载模型..."
    cd "${INSTALL_DIR}/models"
    
    if [ ! -f "model.onnx" ]; then
        curl -L -o "model.onnx" "$MODEL_URL" --progress-bar || {
            echo -e "${RED}  ✗ model.onnx 下载失败${NC}"
            exit 1
        }
    fi
    
    if [ ! -f "model.onnx.data" ]; then
        echo "  下载模型数据文件（87MB，可能需要几分钟）..."
        curl -L -o "model.onnx.data" "$MODEL_DATA_URL" --progress-bar || {
            echo -e "${RED}  ✗ model.onnx.data 下载失败${NC}"
            exit 1
        }
    fi
    echo "  ✓ 模型下载完成"
fi

# 安装枢密包
echo -e "${YELLOW}[5/5] 安装枢密...${NC}"
pip3 install -e "$INSTALL_DIR" --quiet --break-system-packages 2>/dev/null || \
pip3 install -e "$INSTALL_DIR" --quiet 2>/dev/null
echo "  ✓ 安装完成"

# 配置OpenClaw
echo ""
echo -e "${YELLOW}配置OpenClaw...${NC}"

CONFIG_FILE="${HOME}/.openclaw/config.yaml"

# 检查是否已有shumi配置
if [ -f "$CONFIG_FILE" ]; then
    if grep -q "shumi.plugins.openclaw_hook" "$CONFIG_FILE" 2>/dev/null; then
        echo "  ✓ OpenClaw已配置shumi"
    else
        echo "  添加shumi配置到OpenClaw..."
        # 备份原配置
        cp "$CONFIG_FILE" "${CONFIG_FILE}.backup.$(date +%Y%m%d)"
        
        cat >> "$CONFIG_FILE" << 'EOF'

# 枢密 (Shumi) 安全配置
preprocessors:
  - shumi.plugins.openclaw_hook:SecurityAuditHook
postprocessors:
  - shumi.plugins.openclaw_hook:SecurityAuditHook
shumi:
  min_confidence: 0.55
  model_path: ~/.shumi/models/model.onnx
EOF
        echo "  ✓ 配置已添加"
    fi
else
    # 创建新配置
    mkdir -p "${HOME}/.openclaw"
    cat > "$CONFIG_FILE" << 'EOF'
# OpenClaw 配置文件
# 枢密 (Shumi) 已启用

preprocessors:
  - shumi.plugins.openclaw_hook:SecurityAuditHook
postprocessors:
  - shumi.plugins.openclaw_hook:SecurityAuditHook

shumi:
  min_confidence: 0.55
  model_path: ~/.shumi/models/model.onnx

logging:
  level: INFO
EOF
    echo "  ✓ 新配置已创建"
fi

# 创建安全目录和事件目录
mkdir -p "${HOME}/.openclaw/security/events"

# 安装并启动 Shumi Agent
echo ""
echo -e "${YELLOW}安装 Shumi Agent...${NC}"

# 创建事件目录
mkdir -p "${HOME}/.openclaw/security/events"

# 安装 systemd 服务（如果系统支持 systemd）
if command -v systemctl &> /dev/null; then
    SERVICE_FILE="/etc/systemd/system/shumi-agent.service"
    
    if [ -f "$SERVICE_FILE" ]; then
        echo "  ✓ systemd 服务已存在"
    else
        echo "  安装 systemd 服务..."
        sudo cp "${INSTALL_DIR}/scripts/shumi-agent.service" "$SERVICE_FILE" 2>/dev/null || {
            echo "  ⚠️  无法安装 systemd 服务（可能需要 sudo 权限）"
            echo "     手动运行: sudo cp ${INSTALL_DIR}/scripts/shumi-agent.service /etc/systemd/system/"
            echo "     然后: sudo systemctl enable --now shumi-agent"
        }
        
        if [ -f "$SERVICE_FILE" ]; then
            sudo systemctl daemon-reload
            sudo systemctl enable shumi-agent
            sudo systemctl start shumi-agent
            echo "  ✓ Shumi Agent 已启动"
        fi
    fi
else
    echo "  ℹ️  未检测到 systemd，Shumi Agent 需要手动运行:"
    echo "     python3 ${INSTALL_DIR}/src/shumi/agent/shumi_agent.py"
fi

echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}  安装完成！${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo "📁 安装位置: ${INSTALL_DIR}"
echo "🧠 模型位置: ${INSTALL_DIR}/models/"
echo "🤖 Agent位置: ${INSTALL_DIR}/src/shumi/agent/shumi_agent.py"
echo "⚡ 加载速度: ~0.16秒"
echo "💾 内存占用: ~96MB"
echo "🔒 安全配置: ${HOME}/.openclaw/config.yaml"
echo "📋 事件日志: ${HOME}/.openclaw/security/events/shumi.events.jsonl"
echo ""
echo "架构说明:"
echo "  - Hook: OpenClaw插件，检测并加密敏感信息"
echo "  - Agent: 独立进程，监听事件并发送通知"
echo ""
echo "运行测试:"
echo "  cd ${INSTALL_DIR} && python3 -m pytest tests/test_integration.py -v"
echo ""
echo "查看 Agent 状态:"
echo "  sudo systemctl status shumi-agent"
echo "  sudo journalctl -u shumi-agent -f"
echo ""
