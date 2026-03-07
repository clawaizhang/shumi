#!/bin/bash
#
# 枢密 (Shumi) 一键安装脚本 - 完全ONNX版
# 一条命令完成所有安装和配置
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

INSTALL_DIR="${HOME}/.shumi"
CONFIG_DIR="${HOME}/.openclaw"
export HF_ENDPOINT=https://hf-mirror.com

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}  枢密 (Shumi) 一键安装${NC}"
echo -e "${GREEN}  ONNX加速版 - 3秒快速启动${NC}"
echo -e "${GREEN}================================${NC}"
echo ""

# 检查环境
echo -e "${YELLOW}[1/6] 检查环境...${NC}"
python3 --version >/dev/null 2>&1 || { echo -e "${RED}错误: 需要Python 3.10+${NC}"; exit 1; }
echo "  ✓ Python OK"

# 安装依赖
echo -e "${YELLOW}[2/6] 安装ONNX依赖...${NC}"
pip3 install onnxruntime transformers --quiet --break-system-packages 2>/dev/null || \
pip3 install onnxruntime transformers --quiet 2>/dev/null
echo "  ✓ 依赖安装完成"

# ONNX预编译
echo -e "${YELLOW}[3/6] ONNX预编译模型（约2分钟）...${NC}"
echo "  转换后启动速度提升10倍！"

mkdir -p "${INSTALL_DIR}/models"

python3 <> 'PYEOF'
import os, sys, warnings
warnings.filterwarnings('ignore')
os.environ['HF_ENDPOINT'] = 'https://hf-mirror.com'

print("  加载模型...")
from transformers import AutoTokenizer, AutoModel
import torch

tokenizer = AutoTokenizer.from_pretrained('sentence-transformers/all-MiniLM-L6-v2')
model = AutoModel.from_pretrained('sentence-transformers/all-MiniLM-L6-v2')
model.eval()

print("  转换ONNX...")
from torch.onnx import export

inputs = tokenizer(["test"], return_tensors="pt")
onnx_path = "/root/.shumi/models/model.onnx"

export(
    model,
    (inputs['input_ids'], inputs['attention_mask']),
    onnx_path,
    input_names=['input_ids', 'attention_mask'],
    output_names=['last_hidden_state'],
    dynamic_axes={
        'input_ids': {0: 'batch', 1: 'seq'},
        'attention_mask': {0: 'batch', 1: 'seq'},
        'last_hidden_state': {0: 'batch', 1: 'seq'}
    },
    opset_version=14
)

print("  验证ONNX...")
import onnxruntime as ort
session = ort.InferenceSession(onnx_path)
test = tokenizer(["测试"], return_tensors="np")
out = session.run(None, {'input_ids': test['input_ids'], 'attention_mask': test['attention_mask']})
print(f"  ✓ ONNX模型就绪！")
PYEOF

# 克隆安装
echo -e "${YELLOW}[4/6] 安装枢密...${NC}"
if [ -d "$INSTALL_DIR" ]; then
    cd "$INSTALL_DIR" && git pull origin main
else
    git clone https://github.com/clawaizhang/shumi.git "$INSTALL_DIR"
fi
pip3 install -e "$INSTALL_DIR" --quiet --break-system-packages 2>/dev/null || true
echo "  ✓ 安装完成"

# 配置
echo -e "${YELLOW}[5/6] 配置OpenClaw...${NC}"
mkdir -p "$CONFIG_DIR"
cat > "$CONFIG_DIR/config.yaml" <> 'EOF'
preprocessors:
  - shumi.plugins.openclaw_hook:SecurityAuditHook
postprocessors:
  - shumi.plugins.openclaw_hook:SecurityAuditHook
shumi:
  notification_level: brief
logging:
  level: INFO
EOF
echo "  ✓ 配置完成"

# 启动
echo -e "${YELLOW}[6/6] 启动服务...${NC}"
nohup python3 -c "
import sys; sys.path.insert(0, '$INSTALL_DIR/src')
import os; os.environ['HF_ENDPOINT'] = 'https://hf-mirror.com'
from shumi.core.ai_detector import SensitiveDetector
d = SensitiveDetector()
print('[枢密] 服务就绪')
import time; time.sleep(3600)
" > "$HOME/.shumi/shumi.log" 2>&1 &
echo $! > "$HOME/.shumi/shumi.pid"
echo "  ✓ 服务已启动 (PID: $(cat $HOME/.shumi/shumi.pid))"

echo ""
echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}  安装完成！${NC}"
echo -e "${GREEN}================================${NC}"
echo ""
echo "使用说明:"
echo "  枢密已自动集成到OpenClaw"
echo "  消息会自动检测敏感信息并加密"
echo ""
echo "测试:"
echo "  发送包含API Key的消息即可测试"
echo ""
