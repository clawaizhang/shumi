# 用户指南

## 快速开始

### 1. 安装

```bash
# 克隆仓库
git clone https://github.com/clawaizhang/openclaw-security-plugin.git
cd openclaw-security-plugin

# 运行安装脚本
./scripts/install.sh

# 或使用pip安装
pip install -e .
```

### 2. 配置SSH公钥

```bash
# 生成SSH密钥对（如果还没有）
ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa

# 配置插件使用公钥
ai-security config set-public-key ~/.ssh/id_rsa.pub
```

### 3. 配置OpenClaw集成

编辑 `~/.openclaw/config.yaml`:

```yaml
preprocessors:
  - ai_security_audit.plugins.openclaw_hook:SecurityAuditHook
```

## CLI命令参考

### 配置管理

```bash
# 初始化配置
ai-security config init

# 设置公钥
ai-security config set-public-key ~/.ssh/id_rsa.pub

# 查看配置
ai-security config show
```

### 敏感信息扫描

```bash
# 扫描文件
ai-security scan config.ini

# 扫描并自动脱敏
ai-security scan config.ini --fix --output config.ini.secure
```

### 解密占位符

```bash
# 解密单个占位符（需要私钥）
ai-security decrypt <SECURE_APIKEY_ABC123>

# 从文件中解密所有占位符
ai-security decrypt --file message.txt

# 交互式解密
ai-security decrypt --interactive
```

### 审计日志

```bash
# 查看最近50条日志
ai-security audit logs

# 按类型过滤
ai-security audit logs --type encryption

# 查看统计信息
ai-security audit stats

# 验证日志完整性
ai-security audit verify
```

### 状态检查

```bash
# 检查插件状态
ai-security status
```

## 工作原理

1. **检测阶段**: 使用正则表达式识别敏感信息
2. **加密阶段**: RSA-4096 + AES-256-GCM 加密
3. **替换阶段**: 将敏感信息替换为占位符
4. **传输阶段**: 只有占位符被发送给AI
5. **解密阶段**: 本地私钥解密恢复原始值

## 安全注意事项

- 私钥 (`~/.ssh/id_rsa`) 必须严格保密
- 公钥 (`~/.ssh/id_rsa.pub`) 可以安全共享
- 审计日志 (`~/.openclaw/security/audit.log`) 记录所有操作
- 加密数据存储在 `~/.openclaw/security/`
- 所有文件权限设置为仅所有者可读写

## 故障排除

### 问题：无法加载公钥

```bash
# 检查公钥文件是否存在
ls -la ~/.ssh/id_rsa.pub

# 重新设置公钥
ai-security config set-public-key ~/.ssh/id_rsa.pub
```

### 问题：解密失败

```bash
# 确认私钥存在
ls -la ~/.ssh/id_rsa

# 检查私钥权限（应为600）
chmod 600 ~/.ssh/id_rsa

# 使用交互式解密查看详细错误
ai-security decrypt --interactive
```

### 问题：OpenClaw集成不工作

```bash
# 检查插件状态
ai-security status

# 查看详细日志
ai-security --verbose status
```

## 获取帮助

- GitHub Issues: https://github.com/clawaizhang/openclaw-security-plugin/issues
- 文档: https://github.com/clawaizhang/openclaw-security-plugin/tree/main/docs
