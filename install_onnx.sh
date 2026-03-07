#!/bin/bash
#
# 枢密 (Shumi) 一键安装脚本 - ONNX优化版
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

INSTALL_DIR="${HOME}/.shumi"
export HF_ENDPOINT=https://hf-mirror.com

echo -e "${GREEN}================================${NC}"
echo -e "${GREEN}  枢密 (Shumi) 安装脚本 (ONNX版)${NC}"
echo -e "${GREEN}================================${NC}"
echo ""

# 步骤1-3: 检查环境、安装依赖、下载模型
echo -e "${YELLOW}[1-3/8] 环境检查、依赖安装、模型下载...${NC}"

# 步骤4: ONNX预编译
echo -e "${YELLOW}[4/8] ONNX预编译（关键步骤，约2-3分钟）...${NC}"

mkdir -p "${INSTALL_DIR}/models"

python3 <> 'PYEOF'
import os, sys, warnings
warnings.filterwarnings('ignore')
os.environ['HF_ENDPOINT'] = 'https://hf-mirror.com'

print("  加载PyTorch模型...")
from transformers import AutoTokenizer, AutoModel
import torch

tokenizer = AutoTokenizer.from_pretrained('sentence-transformers/all-MiniLM-L6-v2')
model = AutoModel.from_pretrained('sentence-transformers/all-MiniLM-L6-v2')
model.eval()

print("  导出ONNX...")
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
print(f"  ✓ 成功！输出维度: {out[0].shape}")
PYEOF

echo ""
echo -e "${GREEN}✓ ONNX预编译完成！${NC}"
echo ""
