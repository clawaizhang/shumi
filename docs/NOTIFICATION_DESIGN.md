# 用户通知机制设计

## 原则

**"枢密"作为 OpenClaw 插件，使用框架统一的通知机制，不自建渠道。**

## 设计方案

### 1. 使用 OpenClaw 标准日志

```python
# shumi/core/notifier.py
import logging

logger = logging.getLogger('shumi')

class ShumiNotifier:
    """
    通知器 - 使用 OpenClaw 统一日志机制
    """
    
    def __init__(self, config=None):
        self.config = config or {}
        self.level = self.config.get('notification_level', 'brief')
        # level: silent | brief | detailed
    
    def on_encryption(self, count, types):
        """加密完成通知"""
        if count == 0:
            return  # 无敏感信息，静默
        
        if self.level == 'silent':
            return
        
        if self.level == 'brief':
            logger.info(f"枢密：已加密 {count} 个敏感信息")
        
        if self.level == 'detailed':
            logger.info(f"枢密：检测到 {count} 个敏感信息（{', '.join(set(types))}），已加密保护")
    
    def on_decryption(self, count):
        """解密完成通知"""
        if count == 0:
            return  # 无占位符，静默
        
        if self.level == 'silent':
            return
        
        if self.level == 'brief':
            logger.info(f"枢密：已解密 {count} 个占位符")
        
        if self.level == 'detailed':
            logger.info(f"枢密：AI响应中的 {count} 个占位符已解密")
    
    def on_no_sensitive_data(self):
        """无敏感信息 - 完全静默"""
        pass  # 不输出任何日志
```

### 2. 用户配置

```yaml
# ~/.openclaw/config.yaml
logging:
  level: INFO  # 控制日志级别
  format: "%(asctime)s - %(name)s - %(message)s"

plugins:
  shumi:
    notification_level: brief  # silent | brief | detailed
```

### 3. 通知场景

| 场景 | 输入 | 输出 | 日志 |
|------|------|------|------|
| **有敏感信息** | "我的Key是 sk-xxx" | "我的Key是 <SECURE_xxx>" | ✅ "枢密：已加密 1 个敏感信息" |
| **有占位符** | AI返回"<SECURE_xxx>" | 解密后的原文 | ✅ "枢密：已解密 1 个占位符" |
| **无敏感信息** | "普通文本" | 原文 | ❌ **静默，无日志** |

### 4. 关键原则

- **无敏感信息 = 完全静默**：用户感觉不到插件存在
- **有敏感信息 = 简洁通知**：只告知数量和类型，不暴露具体内容
- **使用 OpenClaw 日志**：不自建通知渠道（飞书/邮件等）
- **可配置级别**：用户可选择静默/简略/详细

## 实施计划

1. 创建 `shumi/core/notifier.py`
2. 在 `SecurityAuditHook` 中集成通知器
3. 单元测试验证通知逻辑
4. 更新文档说明配置方式
