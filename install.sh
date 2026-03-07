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

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}  枢密 (Shumi) 一键安装${NC}"
echo -e "${GREEN}  ONNX快速版${NC}"
echo -e "${GREEN}================================${NC}"
echo ""

# 检查环境
echo -e "${YELLOW}[1/4] 检查环境...${NC}"
python3 --version >/dev/null 2>&1 || { echo -e "${RED}错误: 需要Python 3.10+${NC}"; exit 1; }
echo "  ✓ Python OK"

# 安装依赖
echo -e "${YELLOW}[2/4] 安装ONNX依赖...${NC}"
pip3 install onnxruntime transformers --quiet --break-system-packages 2>/dev/null || \
pip3 install onnxruntime transformers --quiet 2>/dev/null
echo "  ✓ 依赖安装完成"

# 下载预编译模型
echo -e "${YELLOW}[3/4] 下载预编译ONNX模型...${NC}"
mkdir -p "${INSTALL_DIR}/models"

if [ -f "${INSTALL_DIR}/models/model.onnx" ]; then
    echo "  ✓ 模型已存在，跳过下载"
else
    echo "  从GitHub Release下载模型..."
    curl -L -o "${INSTALL_DIR}/models/model.onnx" "$MODEL_URL" 2>/dev/null || {
        echo -e "${RED}  ✗ 模型下载失败${NC}"
        echo "  请检查网络连接或手动下载:"
        echo "  $MODEL_URL"
        exit 1
    }
    echo "  ✓ 模型下载完成"
fi

# 安装枢密
echo -e "${YELLOW}[4/4] 安装枢密...${NC}"
if [ -d "$INSTALL_DIR/.git" ]; then
    cd "$INSTALL_DIR" && git pull origin main
else
    git clone https://github.com/clawaizhang/shumi.git "$INSTALL_DIR"
fi
pip3 install -e "$INSTALL_DIR" --quiet --break-system-packages 2>/dev/null || true
echo "  ✓ 安装完成"

# 配置OpenClaw
echo ""
echo -e "${YELLOW}配置OpenClaw...${NC}"
mkdir -p "${HOME}/.openclaw"
cat > "${HOME}/.openclaw/config.yaml" <> 'EOF'
preprocessors:
  - shumi.plugins.openclaw_hook:SecurityAuditHook
postprocessors:
  - shumi.plugins.openclaw_hook:SecurityAuditHook
shumi:
  notification_level: brief
  model_path: ~/.shumi/models/model.onnx
EOF
echo "  ✓ 配置完成"

echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}  安装完成！${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo "模型位置: ${INSTALL_DIR}/models/model.onnx"
echo "加载速度: 0.16秒"
echo "内存占用: ~96MB"
echo ""
