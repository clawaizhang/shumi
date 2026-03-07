"""
通知器 - 使用 OpenClaw 统一日志机制
"""

import logging
from typing import List, Optional

logger = logging.getLogger('shumi')


class ShumiNotifier:
    """
    枢密通知器
    
    设计原则：
    1. 无敏感信息时完全静默
    2. 使用 OpenClaw 标准日志机制
    3. 不自建通知渠道（飞书/邮件等）
    """
    
    # 通知级别
    LEVEL_SILENT = 'silent'      # 完全静默
    LEVEL_BRIEF = 'brief'        # 简略通知（默认）
    LEVEL_DETAILED = 'detailed'  # 详细通知
    
    def __init__(self, level: str = 'brief'):
        """
        初始化通知器
        
        Args:
            level: 通知级别 - silent/brief/detailed
        """
        self.level = level
    
    def on_encryption(self, count: int, types: List[str]):
        """
        加密完成通知
        
        Args:
            count: 加密的敏感信息数量
            types: 敏感信息类型列表
        """
        if count == 0:
            return  # 无敏感信息，静默
        
        if self.level == self.LEVEL_SILENT:
            return
        
        if self.level == self.LEVEL_BRIEF:
            logger.info(f"🔒 枢密：已加密 {count} 个敏感信息")
        
        elif self.level == self.LEVEL_DETAILED:
            unique_types = list(set(types))
            type_str = ', '.join(unique_types)
            logger.info(f"🔒 枢密：检测到 {count} 个敏感信息（{type_str}），已加密保护")
    
    def on_decryption(self, count: int, placeholder_count: int = 0):
        """
        解密完成通知
        
        Args:
            count: 解密的占位符数量
            placeholder_count: 文本中占位符总数（可选）
        """
        if count == 0:
            return  # 无占位符，静默
        
        if self.level == self.LEVEL_SILENT:
            return
        
        if self.level == self.LEVEL_BRIEF:
            logger.info(f"🔓 枢密：已解密 {count} 个占位符")
        
        elif self.level == self.LEVEL_DETAILED:
            if placeholder_count > count:
                logger.info(f"🔓 枢密：已解密 {count}/{placeholder_count} 个占位符（部分可能无法解密）")
            else:
                logger.info(f"🔓 枢密：AI响应中的 {count} 个占位符已解密")
    
    def on_detection_failed(self, error: str):
        """
        检测失败通知（仅详细模式）
        
        Args:
            error: 错误信息
        """
        if self.level == self.LEVEL_DETAILED:
            logger.warning(f"⚠️  枢密：敏感信息检测失败 - {error}")
    
    def on_no_sensitive_data(self):
        """
        无敏感信息 - 完全静默
        
        这是设计关键：用户无感知，不输出任何日志
        """
        pass  # 静默处理


# 便捷函数
def create_notifier(config: Optional[dict] = None) -> ShumiNotifier:
    """
    从配置创建通知器
    
    Args:
        config: 配置字典，包含 notification_level
        
    Returns:
        ShumiNotifier实例
    """
    if config is None:
        config = {}
    
    level = config.get('notification_level', 'brief')
    return ShumiNotifier(level=level)
