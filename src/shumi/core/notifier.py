"""
通知器 - 支持独立消息发送
"""

import logging
from typing import List, Optional, Callable

logger = logging.getLogger('shumi')


class ShumiNotifier:
    """
    枢密通知器
    
    设计原则：
    1. 无敏感信息时完全静默
    2. 支持独立消息发送（不混杂在正常回复中）
    3. 简洁通知，一条消息说明检测结果
    """
    
    # 通知级别
    LEVEL_SILENT = 'silent'      # 完全静默
    LEVEL_BRIEF = 'brief'        # 简略通知（默认）
    LEVEL_DETAILED = 'detailed'  # 详细通知
    
    def __init__(self, level: str = 'brief', message_callback: Optional[Callable] = None):
        """
        初始化通知器
        
        Args:
            level: 通知级别 - silent/brief/detailed
            message_callback: 消息发送回调函数，用于发送独立消息
        """
        self.level = level
        self._message_callback = message_callback
    
    def set_message_callback(self, callback: Callable):
        """设置消息发送回调"""
        self._message_callback = callback
    
    def _send_notification(self, message: str):
        """发送通知 - 优先使用独立消息，否则用日志"""
        if self._message_callback:
            try:
                self._message_callback(message)
                return
            except Exception as e:
                logger.error(f"发送独立消息失败: {e}")
        
        # 降级到日志
        logger.info(message)
    
    def on_encryption(self, count: int, types: List[str]):
        """
        加密完成通知 - 简洁模式只输出一条
        
        Args:
            count: 加密的敏感信息数量
            types: 敏感信息类型列表
        """
        if count == 0:
            return  # 无敏感信息，静默
        
        if self.level == self.LEVEL_SILENT:
            return
        
        if self.level == self.LEVEL_BRIEF:
            # 简洁通知：只输出检测到了哪些类型
            unique_types = list(set(types))
            type_names = {
                'api_key': 'API密钥',
                'password': '密码',
                'token': '令牌',
                'aws_key': 'AWS密钥',
                'private_key': '私钥'
            }
            type_str = '、'.join([type_names.get(t, t) for t in unique_types])
            self._send_notification(f"🔒 枢密：检测到{type_str}，已加密保护")
        
        elif self.level == self.LEVEL_DETAILED:
            unique_types = list(set(types))
            type_str = ', '.join(unique_types)
            self._send_notification(f"🔒 枢密：检测到 {count} 个敏感信息（{type_str}），已加密保护")
    
    def on_decryption(self, count: int, placeholder_count: int = 0):
        """
        解密完成通知 - 简洁模式下静默
        
        Args:
            count: 解密的占位符数量
            placeholder_count: 文本中占位符总数（可选）
        """
        if count == 0:
            return  # 无占位符，静默
        
        if self.level == self.LEVEL_SILENT:
            return
        
        if self.level == self.LEVEL_BRIEF:
            # 简洁模式：解密过程静默，不打扰用户
            pass
        
        elif self.level == self.LEVEL_DETAILED:
            if placeholder_count > count:
                self._send_notification(f"🔓 枢密：已解密 {count}/{placeholder_count} 个占位符（部分可能无法解密）")
            else:
                self._send_notification(f"🔓 枢密：AI响应中的 {count} 个占位符已解密")
    
    def on_detection_failed(self, error: str):
        """
        检测失败通知（仅详细模式）
        
        Args:
            error: 错误信息
        """
        if self.level == self.LEVEL_DETAILED:
            self._send_notification(f"⚠️ 枢密：敏感信息检测失败 - {error}")
    
    def on_no_sensitive_data(self):
        """
        无敏感信息 - 完全静默
        
        这是设计关键：用户无感知，不输出任何日志
        """
        pass  # 静默处理


# 便捷函数
def create_notifier(config: Optional[dict] = None, message_callback: Optional[Callable] = None) -> ShumiNotifier:
    """
    从配置创建通知器
    
    Args:
        config: 配置字典，包含 notification_level
        message_callback: 消息发送回调函数
        
    Returns:
        ShumiNotifier实例
    """
    if config is None:
        config = {}
    
    level = config.get('notification_level', 'brief')
    return ShumiNotifier(level=level, message_callback=message_callback)
