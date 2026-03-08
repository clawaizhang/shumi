"""
Shumi 事件发布模块
用于向 Agent 发送检测事件
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path


class ShumiEventPublisher:
    """
    Shumi 事件发布器
    
    发布带 shumi. 命名空间的事件，供 Shumi Agent 监听
    """
    
    # 事件类型常量
    EVENT_DETECTION = "shumi.detection"      # 检测到敏感信息
    EVENT_ENCRYPTION = "shumi.encryption"    # 加密完成
    EVENT_DECRYPTION = "shumi.decryption"    # 解密完成
    EVENT_ERROR = "shumi.error"              # 错误事件
    
    def __init__(self, events_dir: Optional[str] = None):
        """
        初始化事件发布器
        
        Args:
            events_dir: 事件文件目录，默认 ~/.openclaw/security/events
        """
        if events_dir is None:
            events_dir = os.path.expanduser("~/.openclaw/security/events")
        
        self.events_dir = Path(events_dir)
        self.events_dir.mkdir(parents=True, exist_ok=True)
        
        # 事件文件路径
        self.events_file = self.events_dir / "shumi.events.jsonl"
    
    def _generate_event_id(self) -> str:
        """生成 Shumi 专属事件ID"""
        import uuid
        return f"shumi-{uuid.uuid4().hex[:16]}"
    
    def _write_event(self, event: Dict[str, Any]):
        """写入事件到文件"""
        try:
            with open(self.events_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
                f.flush()
        except Exception as e:
            # 写入失败不阻塞主流程
            import logging
            logging.getLogger('shumi').debug(f"Failed to write event: {e}")
    
    def publish_detection(self, 
                         chat_id: str,
                         channel: str,
                         detected_types: list,
                         confidence: float,
                         placeholder_count: int,
                         message_preview: str,
                         actor: str = "shumi.hook") -> str:
        """
        发布检测事件
        
        Args:
            chat_id: 聊天ID
            channel: 渠道 (feishu/discord/等)
            detected_types: 检测到的类型列表
            confidence: 置信度
            placeholder_count: 占位符数量
            message_preview: 消息预览（脱敏）
            actor: 事件来源
            
        Returns:
            事件ID
        """
        event_id = self._generate_event_id()
        
        event = {
            # Shumi 专属标识
            "event_id": event_id,
            "event_type": self.EVENT_DETECTION,
            "source": "shumi",
            "version": "1.0",
            
            # 时间戳
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "timestamp_ms": int(datetime.utcnow().timestamp() * 1000),
            
            # 上下文
            "context": {
                "chat_id": chat_id,
                "channel": channel,
                "actor": actor,
            },
            
            # 检测详情
            "payload": {
                "detected_types": detected_types,
                "confidence": round(confidence, 3),
                "placeholder_count": placeholder_count,
                "message_preview": message_preview[:100] if message_preview else "",  # 限制长度
            },
            
            # 元数据
            "meta": {
                "processed": False,  # Agent 处理后会设为 True
                "priority": "normal",
            }
        }
        
        self._write_event(event)
        return event_id
    
    def publish_encryption(self,
                          chat_id: str,
                          channel: str,
                          placeholder_id: str,
                          encryption_type: str,
                          actor: str = "shumi.hook") -> str:
        """发布加密事件"""
        event_id = self._generate_event_id()
        
        event = {
            "event_id": event_id,
            "event_type": self.EVENT_ENCRYPTION,
            "source": "shumi",
            "version": "1.0",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "timestamp_ms": int(datetime.utcnow().timestamp() * 1000),
            "context": {
                "chat_id": chat_id,
                "channel": channel,
                "actor": actor,
            },
            "payload": {
                "placeholder_id": placeholder_id,
                "encryption_type": encryption_type,
            },
            "meta": {
                "processed": False,
                "priority": "normal",
            }
        }
        
        self._write_event(event)
        return event_id
    
    def publish_error(self,
                     chat_id: Optional[str],
                     channel: Optional[str],
                     error_type: str,
                     error_message: str,
                     actor: str = "shumi.hook") -> str:
        """发布错误事件"""
        event_id = self._generate_event_id()
        
        event = {
            "event_id": event_id,
            "event_type": self.EVENT_ERROR,
            "source": "shumi",
            "version": "1.0",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "timestamp_ms": int(datetime.utcnow().timestamp() * 1000),
            "context": {
                "chat_id": chat_id or "unknown",
                "channel": channel or "unknown",
                "actor": actor,
            },
            "payload": {
                "error_type": error_type,
                "error_message": error_message[:200],  # 限制长度
            },
            "meta": {
                "processed": False,
                "priority": "high",  # 错误高优先级
            }
        }
        
        self._write_event(event)
        return event_id


# 便捷函数
def create_event_publisher(events_dir: Optional[str] = None) -> ShumiEventPublisher:
    """创建事件发布器"""
    return ShumiEventPublisher(events_dir)
