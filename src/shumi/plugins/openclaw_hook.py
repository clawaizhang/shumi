"""
OpenClaw预处理/后处理Hook - 户部负责
集成到OpenClaw消息预处理和后处理流程

核心功能：
1. 预处理(preprocess): 用户输入 → 加密敏感信息 → 发送给AI
2. 后处理(postprocess): AI响应 → 解密占位符 → 呈现给用户/执行工具
"""

import logging
import re
from typing import Optional, Dict, Any, List
from pathlib import Path

from shumi.core.ai_detector import SensitiveDetector
from shumi.core.encryptor import LocalEncryptor, LocalDecryptor
from shumi.core.placeholder import PlaceholderManager, is_placeholder
from shumi.core.auditor import SecurityAuditor, get_default_auditor
from shumi.core.notifier import ShumiNotifier, create_notifier
from shumi.core.event_publisher import ShumiEventPublisher, create_event_publisher

logger = logging.getLogger(__name__)


class SecurityAuditHook:
    """
    OpenClaw安全审计Hook
    
    双向处理：
    1. 【预处理】用户输入 → 检测敏感信息 → 加密 → 发送给AI
    2. 【后处理】AI响应 → 检测占位符 → 解密 → 呈现给用户
    
    使用方式：
    在OpenClaw配置中添加：
    preprocessors:
      - shumi.plugins.openclaw_hook:SecurityAuditHook
    postprocessors:
      - shumi.plugins.openclaw_hook:SecurityAuditHook
    """
    
    # 类级别变量，用于存储待发送的通知
    _pending_notifications: List[str] = []
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        初始化Hook
        
        Args:
            config: 配置字典
        """
        self._config = config or {}
        self._initialized = False
        
        # 组件
        self._detector: Optional[SensitiveDetector] = None
        self._encryptor: Optional[LocalEncryptor] = None
        self._decryptor: Optional[LocalDecryptor] = None
        self._placeholder_manager: Optional[PlaceholderManager] = None
        self._auditor: Optional[SecurityAuditor] = None
        self._notifier: Optional[ShumiNotifier] = None
        self._event_publisher: Optional[ShumiEventPublisher] = None
        
        self._init_components()
    
    def _init_components(self) -> None:
        """初始化组件"""
        try:
            # 初始化AI检测器（基于ONNX模型）
            model_path = self._config.get('model_path')
            if not model_path:
                model_path = Path.home() / '.shumi' / 'models' / 'model.onnx'
            
            self._detector = SensitiveDetector(str(model_path))
            logger.info(f"AI detector initialized with model: {model_path}")
            
            # 初始化加密器（公钥加密，用于发送给AI前加密）
            public_key_path = self._config.get('public_key_path')
            if public_key_path:
                self._encryptor = LocalEncryptor(public_key_path)
                logger.info(f"Loaded public key from: {public_key_path}")
            else:
                default_paths = [
                    Path.home() / '.ssh' / 'id_rsa.pub',
                    Path.home() / '.ssh' / 'id_ed25519.pub',
                ]
                for path in default_paths:
                    if path.exists():
                        self._encryptor = LocalEncryptor(path)
                        logger.info(f"Loaded public key from default path: {path}")
                        break
            
            # 初始化解密器（私钥解密，用于AI响应后解密）
            private_key_path = self._config.get('private_key_path')
            if private_key_path and Path(private_key_path).exists():
                self._decryptor = LocalDecryptor(private_key_path)
                logger.info(f"Loaded private key from: {private_key_path}")
            else:
                default_private_paths = [
                    Path.home() / '.ssh' / 'id_rsa',
                    Path.home() / '.ssh' / 'id_ed25519',
                ]
                for path in default_private_paths:
                    if path.exists():
                        self._decryptor = LocalDecryptor(path)
                        logger.info(f"Loaded private key from default path: {path}")
                        break
            
            # 初始化占位符管理器
            placeholder_storage = self._config.get('placeholder_storage')
            self._placeholder_manager = PlaceholderManager(placeholder_storage)
            
            # 初始化审计器
            self._auditor = get_default_auditor()
            
            # 初始化通知器（使用独立消息回调）
            self._notifier = create_notifier(
                self._config,
                message_callback=self._add_notification
            )
            
            # 初始化事件发布器（用于Agent通知）
            self._event_publisher = create_event_publisher()
            logger.info("Event publisher initialized")
            
            self._initialized = True
            logger.info("SecurityAuditHook initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize SecurityAuditHook: {e}")
            self._initialized = False
    
    def _add_notification(self, message: str):
        """添加待发送的通知"""
        SecurityAuditHook._pending_notifications.append(message)
        logger.debug(f"Notification queued: {message}")
    
    @classmethod
    def get_and_clear_notifications(cls) -> List[str]:
        """获取并清空待发送的通知列表"""
        notifications = cls._pending_notifications.copy()
        cls._pending_notifications.clear()
        return notifications
    
    # ==================== 预处理：用户输入 → 加密 → 发送给AI ====================
    
    def preprocess(self, text: str, context: Optional[Dict[str, Any]] = None) -> str:
        """
        【预处理】处理用户输入，加密敏感信息后发送给AI
        
        Args:
            text: 用户输入文本
            context: 上下文信息
            
        Returns:
            处理后的文本（敏感信息已替换为占位符）
        """
        if not self._initialized or not self._encryptor or not self._encryptor.is_ready():
            logger.warning("Encryptor not ready, skipping encryption")
            return text
        
        try:
            # AI检测器检测敏感信息
            matches = self._detector.detect(text)
            
            if not matches:
                # 无敏感信息，静默处理，不通知
                return text
            
            # 如果没有加密器，直接返回原文（只检测不加密）
            if not self._encryptor:
                logger.warning("Encryptor not available, returning original text")
                return text
            
            # 记录检测到的类型
            detected_types = [m['category'] for m in matches]
            
            # 从后往前处理，避免位置偏移
            processed_text = text
            encrypted_count = 0
            for match in sorted(matches, key=lambda m: m['start'], reverse=True):
                try:
                    placeholder = self._encrypt_match(match)
                    if placeholder:
                        processed_text = (
                            processed_text[:match['start']] +
                            placeholder +
                            processed_text[:match['end']]
                        )
                        encrypted_count += 1
                except Exception as e:
                    logger.error(f"Failed to encrypt match: {e}")
                    continue
            
            # 通知用户加密完成
            if self._notifier and encrypted_count > 0:
                self._notifier.on_encryption(encrypted_count, detected_types)
            
            # 发布事件给 Agent（如果配置了）
            if self._event_publisher and encrypted_count > 0:
                try:
                    # 从 context 获取聊天信息
                    chat_id = context.get('chat_id') if context else None
                    channel = context.get('channel') if context else None
                    
                    if chat_id and channel:
                        # 计算最高置信度
                        max_confidence = max(m.get('confidence', 0) for m in matches)
                        
                        # 生成脱敏预览
                        preview = text[:50] + "..." if len(text) > 50 else text
                        
                        self._event_publisher.publish_detection(
                            chat_id=chat_id,
                            channel=channel,
                            detected_types=list(set(detected_types)),  # 去重
                            confidence=max_confidence,
                            placeholder_count=encrypted_count,
                            message_preview=preview
                        )
                        logger.debug(f"Published detection event for chat {chat_id}")
                except Exception as e:
                    logger.debug(f"Failed to publish event: {e}")
            
            return processed_text
            
        except Exception as e:
            logger.error(f"Error during preprocessing: {e}")
            return text
    
    def _encrypt_match(self, match: Dict[str, Any]) -> Optional[str]:
        """加密单个匹配项，返回占位符"""
        # 加密敏感信息
        matched_text = match['text']
        encrypted_blob = self._encryptor.encrypt(matched_text)
        
        # 创建占位符
        placeholder = self._placeholder_manager.create_placeholder(
            encrypted_blob,
            match['category'],
            metadata={
                'confidence': match['confidence'],
                'original_length': len(matched_text)
            }
        )
        
        # 记录审计日志
        self._auditor.log_detection(match, placeholder, actor="shumi_preprocess")
        self._auditor.log_encryption(
            placeholder,
            match['category'],
            self._encryptor.get_key_fingerprint() or 'unknown',
            actor="shumi_preprocess"
        )
        
        logger.debug(f"Encrypted {match['category']}: {matched_text[:10]}... -> {placeholder}")
        
        return placeholder
    
    # ==================== 后处理：AI响应 → 解密 → 呈现给用户 ====================
    
    def postprocess(self, text: str, context: Optional[Dict[str, Any]] = None) -> str:
        """
        【后处理】处理AI响应，解密占位符后呈现给用户
        
        Args:
            text: AI响应文本（可能包含占位符）
            context: 上下文信息
            
        Returns:
            处理后的文本（占位符已解密为原始值）
        """
        if not self._initialized or not self._decryptor:
            logger.warning("Decryptor not ready, skipping decryption")
            return text
        
        try:
            # 从文本中提取所有占位符
            placeholders = self._placeholder_manager.extract_placeholders_from_text(text)
            
            if not placeholders:
                # 无占位符，静默处理
                return text
            
            # 解密并替换每个占位符
            processed_text = text
            decrypted_count = 0
            for placeholder in placeholders:
                try:
                    decrypted_text = self._decrypt_placeholder(placeholder)
                    if decrypted_text:
                        processed_text = processed_text.replace(placeholder, decrypted_text)
                        decrypted_count += 1
                except Exception as e:
                    logger.error(f"Failed to decrypt placeholder {placeholder}: {e}")
                    continue
            
            # 通知用户解密完成
            if self._notifier and decrypted_count > 0:
                self._notifier.on_decryption(decrypted_count, len(placeholders))
            
            return processed_text
            
        except Exception as e:
            logger.error(f"Error during postprocessing: {e}")
            return text
    
    def _decrypt_placeholder(self, placeholder: str) -> Optional[str]:
        """解密单个占位符，返回原始值"""
        # 从占位符管理器获取加密数据
        encrypted_blob = self._placeholder_manager.resolve_placeholder(placeholder)
        
        if not encrypted_blob:
            logger.warning(f"Placeholder not found: {placeholder}")
            return None
        
        # 使用私钥解密
        decrypted_text = self._decryptor.decrypt(encrypted_blob)
        
        # 记录审计日志
        self._auditor.log_decryption(
            placeholder,
            actor="shumi_postprocess",
            success=True
        )
        
        logger.debug(f"Decrypted {placeholder} -> {decrypted_text[:10]}...")
        
        return decrypted_text
    
    # ==================== 工具调用处理 ====================
    
    def process_tool_call(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        处理AI返回的工具调用参数
        
        如果工具调用参数中包含占位符，先解密再执行
        
        Args:
            tool_name: 工具名称
            params: 工具参数
            
        Returns:
            处理后的参数（占位符已解密）
        """
        if not self._initialized or not self._decryptor:
            return params
        
        # 递归处理参数字典中的所有字符串值
        return self._decrypt_params_recursive(params)
    
    def _decrypt_params_recursive(self, obj: Any) -> Any:
        """递归解密参数中的占位符"""
        if isinstance(obj, dict):
            return {k: self._decrypt_params_recursive(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._decrypt_params_recursive(item) for item in obj]
        elif isinstance(obj, str):
            # 检查并解密字符串中的占位符
            placeholders = self._placeholder_manager.extract_placeholders_from_text(obj)
            for placeholder in placeholders:
                try:
                    decrypted = self._decrypt_placeholder(placeholder)
                    if decrypted:
                        obj = obj.replace(placeholder, decrypted)
                except Exception as e:
                    logger.error(f"Failed to decrypt in params: {e}")
            return obj
        else:
            return obj
    
    # ==================== 状态检查 ====================
    
    def health_check(self) -> Dict[str, Any]:
        """健康检查"""
        checks = {
            'initialized': self._initialized,
            'detector': self._detector is not None,
            'encryptor': self._encryptor is not None and self._encryptor.is_ready(),
            'decryptor': self._decryptor is not None,
            'placeholder_manager': self._placeholder_manager is not None,
            'auditor': self._auditor is not None,
        }
        
        all_healthy = all(checks.values())
        
        return {
            'healthy': all_healthy,
            'checks': checks,
            'message': 'All components healthy' if all_healthy else 'Some components not ready'
        }


# OpenClaw插件接口
class ShumiPlugin:
    """
    OpenClaw插件接口
    
    实现了OpenClaw预处理器和后处理器插件标准接口
    """
    
    def __init__(self):
        self._hook: Optional[SecurityAuditHook] = None
    
    def initialize(self, config: Dict[str, Any]) -> None:
        """初始化插件"""
        self._hook = SecurityAuditHook(config)
    
    def preprocess(self, text: str, context: Optional[Dict[str, Any]] = None) -> str:
        """
        【预处理】处理用户输入
        
        这是OpenClaw调用的预处理方法
        """
        if self._hook is None:
            logger.error("Plugin not initialized")
            return text
        
        return self._hook.preprocess(text, context)
    
    def postprocess(self, text: str, context: Optional[Dict[str, Any]] = None) -> str:
        """
        【后处理】处理AI响应
        
        这是OpenClaw调用的后处理方法
        """
        if self._hook is None:
            logger.error("Plugin not initialized")
            return text
        
        return self._hook.postprocess(text, context)
    
    def process_tool_call(self, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        处理工具调用
        
        在AI返回工具调用后、执行前调用
        """
        if self._hook is None:
            return params
        
        return self._hook.process_tool_call(tool_name, params)
    
    def shutdown(self) -> None:
        """关闭插件"""
        logger.info("ShumiPlugin shutdown")
