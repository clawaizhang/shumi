# AI安全审计插件

> 在消息发给AI之前拦截敏感信息，本地加密存储，绝不发送明文给AI。

## 功能特性

- 🔍 **敏感信息检测**: 自动识别API Key、密码、Token、私钥等敏感信息
- 🔐 **本地加密**: 使用RSA-4096 + AES-256-GCM加密，敏感数据不出本地
- 🛡️ **脱敏替换**: 将敏感信息替换为占位符后再发送给AI
- 📊 **审计日志**: 完整记录所有敏感操作，可追溯可审计
- ⚙️ **OpenClaw集成**: 无缝集成OpenClaw预处理流程

## 快速开始

### 安装

```bash
pip install ai-security-audit
```

### 配置SSH公钥

```bash
# 生成SSH密钥对（如没有）
ssh-keygen -t rsa -b 4096 -f ~/.ssh/ai_security

# 配置插件使用公钥
ai-security config set-public-key ~/.ssh/ai_security.pub
```

### OpenClaw集成

在 `~/.openclaw/config.yaml` 中添加：

```yaml
preprocessors:
  - ai_security_audit.plugins.openclaw_hook:SecurityAuditHook
```

### 使用示例

用户输入包含敏感信息：
```
我的AWS Access Key是 AKIAIOSFODNN7EXAMPLE，Secret Key是 wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

实际发送给AI的内容：
```
我的AWS Access Key是 <SECURE_AWSKEY_a1b2c3d4>，Secret Key是 <SECURE_SECRET_e5f6g7h8>
```

需要查看原始值时：
```bash
ai-security decrypt <SECURE_AWSKEY_a1b2c3d4>
```

## 支持的敏感信息类型

| 类型 | 示例 | 检测方式 |
|------|------|----------|
| API Key | `sk-abc123xyz789` | 正则匹配 |
| AWS Access Key | `AKIAIOSFODNN7EXAMPLE` | 正则匹配 |
| 密码/Secret | `password: mysecret123` | 正则匹配 |
| Token | `token: eyJhbG...` | 正则匹配 |
| JWT | `eyJhbGciOiJIUzI1NiIs...` | 正则匹配 |
| SSH私钥 | `-----BEGIN RSA PRIVATE KEY-----` | 正则匹配 |
| 信用卡号 | `4532015112830366` | Luhn算法验证 |

## 安全架构

```
敏感信息明文
    ↓
检测识别
    ↓
生成随机AES-256-GCM密钥
    ↓
AES加密敏感信息
    ↓
用SSH RSA公钥加密AES密钥
    ↓
存储加密数据到本地
    ↓
替换为占位符发送给AI
```

## 命令行工具

```bash
# 配置管理
ai-security config init              # 初始化配置
ai-security config set-public-key    # 设置加密公钥
ai-security config show              # 查看当前配置

# 解密工具
ai-security decrypt <placeholder>    # 解密占位符
ai-security decrypt --file <path>    # 解密文件中的占位符
ai-security decrypt --interactive    # 交互式解密

# 审计日志
ai-security audit logs               # 查看审计日志
ai-security audit stats              # 查看统计信息

# 敏感信息扫描
ai-security scan <file>              # 扫描文件中的敏感信息
ai-security scan --fix <file>        # 扫描并自动脱敏
```

## 项目结构

```
ai-security-audit/
├── src/ai_security_audit/
│   ├── core/
│   │   ├── detector.py      # 敏感信息检测器
│   │   ├── encryptor.py     # 加密模块
│   │   ├── placeholder.py   # 占位符管理
│   │   └── auditor.py       # 审计日志
│   ├── plugins/
│   │   └── openclaw_hook.py # OpenClaw集成
│   ├── cli/
│   │   └── main.py          # CLI工具
│   └── utils/
│       └── patterns.py      # 敏感信息正则模式
├── tests/                   # 测试用例
├── config/                  # 配置文件
└── docs/                    # 文档
```

## 开发团队

- **工部**: 工程基础设施、CI/CD
- **刑部**: 敏感信息检测规则、安全测试
- **兵部**: 加密模块、密钥管理
- **户部**: OpenClaw集成、配置系统
- **礼部**: CLI工具、用户文档
- **吏部**: 审计系统、测试覆盖

## 许可证

MIT License
