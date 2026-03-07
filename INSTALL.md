# 枢密 (Shumi) - 一键安装指南

## 快速安装

```bash
# 方式1: 直接下载安装脚本
curl -fsSL https://raw.githubusercontent.com/clawaizhang/shumi/main/install.sh | bash

# 方式2: 先下载，再运行
git clone https://github.com/clawaizhang/shumi.git
cd shumi
./install.sh
```

## 安装步骤说明

安装脚本会自动完成以下步骤：

### 1. 环境检查
- Python 3.10+ 版本检查
- pip3 可用性检查
- git 可用性检查

### 2. 安装枢密
- 从 GitHub 克隆最新代码
- 安装 Python 依赖包

### 3. 下载AI模型
- 自动下载 all-MiniLM-L6-v2 (约90MB)
- 首次下载可能需要几分钟

### 4. 初始化配置
- 创建配置目录 `~/.shumi/`
- 生成SSH密钥对（用于加密）

### 5. 集成OpenClaw
- 自动修改 `~/.openclaw/config.yaml`
- 启用预处理器和后处理器

### 6. 验证安装
- 导入测试
- 功能验证

## 安装后配置

配置文件位置：`~/.openclaw/config.yaml`

```yaml
# 枢密配置
shumi:
  notification_level: brief  # 通知级别: silent | brief | detailed
  chunk_strategy_path: ~/.shumi/data/chunk_strategy.json
```

### 通知级别说明

| 级别 | 说明 |
|------|------|
| `silent` | 完全静默，无任何输出 |
| `brief` | 简略通知（推荐），只显示数量 |
| `detailed` | 详细通知，显示敏感信息类型 |

## 卸载

```bash
# 删除安装目录
rm -rf ~/.shumi

# 从OpenClaw配置中移除
# 编辑 ~/.openclaw/config.yaml，删除shumi相关配置
```

## 故障排除

### 问题1: Python版本过低
```
错误: Python版本 3.8.10 过低
```
**解决**: 升级Python到3.10或更高版本

### 问题2: 模型下载失败
```
下载失败: Connection timeout
```
**解决**: 检查网络连接，或使用代理

### 问题3: OpenClaw集成失败
```
错误: 配置文件不存在
```
**解决**: 手动创建 `~/.openclaw/config.yaml`

## 更新

```bash
cd ~/.shumi
git pull origin main
pip3 install -e . --upgrade
```
