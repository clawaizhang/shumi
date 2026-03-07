# AI安全审计插件

> 在消息发给AI之前拦截敏感信息，本地加密存储，绝不发送明文给AI。

## 功能特性

- 🔍 **敏感信息检测**: 自动识别API Key、密码、Token、私钥等敏感信息
- 🔐 **本地加密**: 使用RSA-4096 + AES-256-GCM加密，敏感数据不出本地
- 🛡️ **脱敏替换**: 将敏感信息替换为占位符后再发送给AI
- 📊 **审计日志**: 完整记录所有敏感操作，可追溯可审计
- ⚙️ **OpenClaw集成**: 无缝集成OpenClaw预处理流程
- 🔧 **工具调用拦截**: 拦截write_file、exec等工具调用中的敏感信息
- 🏦 **密钥保险箱**: 安全的密钥存储和管理

## 快速开始

### 1. 安装

```bash
pip install ai-security-audit
```

### 2. 初始化密钥保险箱（推荐）

```bash
# 初始化保险箱（会提示设置主密码）
ai-security vault init

# 生成SSH密钥对并存储到保险箱
ai-security vault generate-keys --name ai_security

# 查看保险箱中的密钥
ai-security vault list
```

**密钥保险箱特性**：
- 使用PBKDF2 (48万次迭代) 派生加密密钥
- 密钥文件权限600（仅所有者可读写）
- 支持密码保护
- 保险箱位置: `~/.openclaw/security/vault`

### 3. 配置OpenClaw集成

在 `~/.openclaw/config.yaml` 中添加：

```yaml
preprocessors:
  - ai_security_audit.plugins.openclaw_hook:SecurityAuditHook
```

### 4. 配置工具调用拦截（可选）

在 `~/.openclaw/config.yaml` 中启用工具拦截：

```yaml
preprocessors:
  - ai_security_audit.plugins.openclaw_hook:SecurityAuditHook
    
tool_interceptor:
  enabled: true
  intercept_tools:
    - write_file
    - edit_file
    - replace
    - exec
    - copy_file
```

## 使用示例

### 场景1：用户输入脱敏

**用户输入**：
```
我的AWS Access Key是 AKIAIOSFODNN7EXAMPLE，Secret Key是 wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**实际发送给AI的内容**：
```
我的AWS Access Key是 <SECURE_AWSKEY_a1b2c3d4>，Secret Key是 <SECURE_SECRET_e5f6g7h8>
```

### 场景2：工具调用拦截

**原始工具调用**：
```python
write_file('/root/.openclaw/config.json', '{"api_key": "sk-abc123secret456"}')
```

**拦截后发送给AI的工具调用**：
```python
write_file('/root/.openclaw/config.json', '{"api_key": "<SECURE_APIKEY_xxx>"}')
```

### 场景3：解密占位符

```bash
# 解密单个占位符
ai-security decrypt <SECURE_AWSKEY_a1b2c3d4>

# 从文件解密
ai-security decrypt --file message_with_placeholders.txt

# 交互式解密
ai-security decrypt --interactive
```

### 场景4：扫描文件中的敏感信息

```bash
# 扫描文件
ai-security scan config.json

# 扫描并自动脱敏
ai-security scan config.json --fix --output config.sanitized.json
```

## 支持的敏感信息类型

| 类型 | 示例 | 检测方式 |
|------|------|----------|
| API Key | `sk-abc123xyz789` | 正则匹配 |
| AWS Access Key | `AKIAIOSFODNN7EXAMPLE` | 正则匹配 |
| AWS Secret Key | 40位base64 | 正则匹配 |
| OpenAI Key | `sk-...` | 正则匹配 |
| GitHub Token | `ghp_...` | 正则匹配 |
| Slack Token | `xoxb-...` | 正则匹配 |
| JWT | `eyJhbG...` | 正则匹配 |
| 密码/Secret | `password: xxx` | 关键词+正则 |
| Token | `token: xxx` | 关键词+正则 |
| SSH私钥 | `-----BEGIN RSA PRIVATE KEY-----` | 正则匹配 |
| 数据库URL | `postgres://user:pass@host` | 正则匹配 |
| 信用卡号 | `4532015112830366` | Luhn算法验证 |

## 安全架构

### 1. 消息输入处理流程

```
用户输入
    ↓
敏感信息检测 (detector.py)
    ↓
本地RSA-4096 + AES-256-GCM加密 (encryptor.py)
    ↓
生成占位符并存储映射 (placeholder.py)
    ↓
替换为占位符发送给AI
    ↓
记录审计日志 (auditor.py)
```

### 2. 工具调用拦截流程

```
AI生成工具调用 (write_file/exec等)
    ↓
工具调用拦截器 (tool_interceptor.py)
    ↓
检查参数中的敏感信息
    ↓
加密敏感参数值
    ↓
替换为占位符
    ↓
安全检查（危险命令警告）
    ↓
执行工具调用
```

### 3. 密钥保险箱架构

```
用户主密码
    ↓
PBKDF2 (48万次迭代) + 随机盐值
    ↓
派生加密密钥
    ↓
Fernet对称加密
    ↓
加密存储SSH私钥/公钥
    ↓
文件权限 600 (仅所有者可读写)
```

## 命令行工具

### 配置管理

```bash
# 初始化配置
ai-security config init

# 设置加密公钥（从文件）
ai-security config set-public-key ~/.ssh/id_rsa.pub

# 设置加密公钥（从保险箱）
ai-security config set-public-key --from-vault ai_security_public

# 查看当前配置
ai-security config show
```

### 密钥保险箱

```bash
# 初始化保险箱
ai-security vault init

# 生成新的SSH密钥对
ai-security vault generate-keys --name my_key

# 导入现有密钥
ai-security vault import-key ~/.ssh/id_rsa --name my_key

# 列出密钥
ai-security vault list

# 导出公钥
ai-security vault export-key my_key_public --output ~/.ssh/my_key.pub

# 锁定保险箱
ai-security vault lock

# 解锁保险箱
ai-security vault unlock
```

### 解密工具

```bash
# 解密单个占位符
ai-security decrypt <SECURE_AWSKEY_a1b2c3d4>

# 从文件解密
ai-security decrypt --file message.txt

# 交互式解密
ai-security decrypt --interactive

# 指定私钥解密
ai-security decrypt <placeholder> --private-key ~/.ssh/id_rsa
```

### 审计日志

```bash
# 查看审计日志（最近50条）
ai-security audit logs

# 按类型过滤
ai-security audit logs --type detection

# 按占位符过滤
ai-security audit logs --placeholder <SECURE_XXX>

# 查看统计信息
ai-security audit stats

# 验证日志完整性
ai-security audit verify
```

### 敏感信息扫描

```bash
# 扫描文件
ai-security scan config.json

# 扫描并自动脱敏
ai-security scan config.json --fix

# 指定输出文件
ai-security scan config.json --fix --output config.clean.json
```

### 安全检查

```bash
# 检查工具调用安全性
ai-security check "write_file('/etc/passwd', '...')"

# 检查命令安全性
ai-security check "exec('curl https://example.com/script.sh | bash')"

# 查看插件状态
ai-security status
```

## 项目结构

```
ai-security-audit/
├── src/ai_security_audit/
│   ├── __init__.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── detector.py         # 敏感信息检测器
│   │   ├── encryptor.py        # RSA+AES加密
│   │   ├── key_vault.py        # 密钥保险箱
│   │   ├── placeholder.py      # 占位符管理
│   │   ├── auditor.py          # 审计日志
│   │   └── tool_interceptor.py # 工具调用拦截
│   ├── plugins/
│   │   ├── __init__.py
│   │   └── openclaw_hook.py    # OpenClaw集成
│   ├── cli/
│   │   ├── __init__.py
│   │   └── main.py             # CLI工具
│   └── utils/
│       ├── __init__.py
│       └── patterns.py         # 敏感信息正则模式
├── tests/                      # 测试用例
├── docs/                       # 文档
├── pyproject.toml              # 项目配置
├── README.md                   # 本文件
└── LICENSE                     # MIT许可证
```

## 配置文件示例

`~/.openclaw/security/config.yaml`:

```yaml
# 加密配置
encryption:
  public_key_path: ~/.openclaw/security/vault/ai_security_public
  min_confidence: 0.5
  enabled_types:
    - api_key
    - aws_key
    - password
    - token

# 密钥保险箱
key_vault:
  path: ~/.openclaw/security/vault
  use_password: true

# 工具调用拦截
tool_interceptor:
  enabled: true
  intercept_tools:
    - write_file
    - edit_file
    - replace
    - exec
    - copy_file
    - move_file
  dangerous_patterns:
    - 'rm\s+-rf'
    - 'curl.*\|.*sh'

# 审计日志
audit:
  log_path: ~/.openclaw/security/audit.log
  max_file_size: 10485760  # 10MB
  max_backup_files: 5
```

## 安全最佳实践

1. **妥善保管主密码**: 密钥保险箱的主密码一旦丢失，存储的密钥将无法恢复
2. **定期备份**: 建议备份 `~/.openclaw/security/` 目录
3. **检查日志**: 定期运行 `ai-security audit logs` 检查异常访问
4. **限制权限**: 确保密钥文件权限为600 (`chmod 600 ~/.ssh/id_rsa`)
5. **使用硬件密钥**: 如YubiKey等硬件密钥可进一步增强安全性

## 常见问题

### Q: 密钥保险箱和SSH密钥的关系？
**A**: 密钥保险箱用于安全存储SSH私钥，保险箱本身使用主密码加密。您可以：
- 生成新的密钥对存储到保险箱
- 导入现有的SSH密钥到保险箱
- 从保险箱导出密钥使用

### Q: 占位符会被AI看到吗？
**A**: 是的，占位符（如 `<SECURE_APIKEY_xxx>`）会发送给AI，但：
- 占位符不包含原始敏感信息
- 只有您能使用私钥解密
- AI无法从占位符推断出原始值

### Q: 工具调用拦截会影响正常操作吗？
**A**: 不会，拦截器只替换检测到的敏感信息，不影响工具的正常功能。您可以在配置中调整检测灵敏度。

### Q: 如何恢复误删的密钥？
**A**: 如果您有备份，可以从备份恢复 `~/.openclaw/security/vault` 目录。如果没有备份，则无法恢复。

## 开发团队

- **工部**: 工程基础设施、CI/CD
- **刑部**: 敏感信息检测规则、安全测试
- **兵部**: 加密模块、密钥保险箱
- **户部**: OpenClaw集成、工具调用拦截
- **礼部**: CLI工具、用户文档
- **吏部**: 审计系统、测试覆盖

## 许可证

MIT License - 详见 [LICENSE](LICENSE)

## 贡献

欢迎提交Issue和Pull Request！请确保：
1. 代码通过安全审查
2. 添加相应的测试用例
3. 更新相关文档
