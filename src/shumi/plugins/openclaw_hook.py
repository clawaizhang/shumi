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

from shumi.core.detector import SensitiveInfoDetector, MatchResult
from shumi.core.ai_detector import AISensitiveDetector
from shumi.core.encryptor import LocalEncryptor, LocalDecryptor
from shumi.core.placeholder import PlaceholderManager, is_placeholder
from shumi.core.auditor import SecurityAuditor, get_default_auditor

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
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        初始化Hook
        
        Args:
            config: 配置字典
        """
        self._config = config or {}
        self._initialized = False
        
        # 组件
        self._detector: Optional[SensitiveInfoDetector] = None
        self._ai_detector: Optional[AISensitiveDetector] = None
        self._encryptor: Optional[LocalEncryptor] = None
        self._decryptor: Optional[LocalDecryptor] = None
        self._placeholder_manager: Optional[PlaceholderManager] = None
        self._auditor: Optional[SecurityAuditor] = None
        
        # 配置
        self._min_confidence = self._config.get('min_confidence', 0.5)
        self._use_ai_detector = self._config.get('use_ai_detector', True)  # 默认启用AI检测器
        
        self._init_components()
    
    def _init_components(self) -> None:
        """初始化组件"""
        try:
            # 初始化检测器
            self._detector = SensitiveInfoDetector()
            
            # 初始化AI检测器（基于Embedding模型）
            if self._use_ai_detector:
                try:
                    chunk_strategy_path = self._config.get('chunk_strategy_path')
                    if not chunk_strategy_path:
                        # 使用默认路径
                        import shumi
                        chunk_strategy_path = Path(shumi.__file__).parent / 'data' / 'chunk_strategy.json'
                    
                    self._ai_detector = AISensitiveDetector(chunk_strategy_path)
                    logger.info(f"AI detector initialized with strategy: {chunk_strategy_path}")
                except Exception as e:
                    logger.warning(f"Failed to initialize AI detector: {e}, falling back to regex only")
                    self._ai_detector = None
            
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
            
            self._initialized = True
            logger.info("SecurityAuditHook initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize SecurityAuditHook: {e}")
            self._initialized = False
    
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
            all_matches = []
            
            # 1. 正则检测器
            regex_matches = self._detector.detect(text, self._min_confidence)
            all_matches.extend(regex_matches)
            
            # 2. AI检测器（如果启用）
            if self._ai_detector:
                ai_matches = self._ai_detector.detect(text)
                # 合并AI检测结果，避免与正则结果重复
                for ai_match in ai_matches:
                    # 检查是否已被正则检测到
                    if not any(rm.start_pos <= ai_match['start'] <= rm.end_pos for rm in regex_matches):
                        all_matches.append(MatchResult(
                            matched_text=ai_match['text'],
                            match_type=ai_match['category'],
                            start_pos=ai_match['start'],
                            end_pos=ai_match['end'],
                            confidence=ai_match['confidence']
                        ))
            
            if not all_matches:
                return text
            
            logger.info(f"[Preprocess] Detected {len(all_matches)} sensitive items to encrypt")
            
            # 从后往前处理，避免位置偏移
            processed_text = text
            for match in sorted(all_matches, key=lambda m: m.start_pos, reverse=True):
                try:
                    placeholder = self._encrypt_match(match)
                    if placeholder:
                        processed_text = (
                            processed_text[:match.start_pos] +
                            placeholder +
                            processed_text[match.end_pos:]
                        )
                except Exception as e:
                    logger.error(f"Failed to encrypt match: {e}")
                    continue
            
            return processed_text
            
        except Exception as e:
            logger.error(f"Error during preprocessing: {e}")
            return text
    
    def _encrypt_match(self, match: MatchResult) -> Optional[str]:
        """加密单个匹配项，返回占位符"""
        # 加密敏感信息
        encrypted_blob = self._encryptor.encrypt(match.matched_text)
        
        # 创建占位符
        placeholder = self._placeholder_manager.create_placeholder(
            encrypted_blob,
            match.match_type,
            metadata={
                'confidence': match.confidence,
                'original_length': len(match.matched_text)
            }
        )
        
        # 记录审计日志
        self._auditor.log_detection(match, placeholder, actor="shumi_preprocess")
        self._auditor.log_encryption(
            placeholder,
            match.match_type,
            self._encryptor.get_key_fingerprint() or 'unknown',
            actor="shumi_preprocess"
        )
        
        logger.debug(f"Encrypted {match.match_type}: {match.matched_text[:10]}... -> {placeholder}")
        
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
                return text
            
            logger.info(f"[Postprocess] Detected {len(placeholders)} placeholders to decrypt")
            
            # 解密并替换每个占位符
            processed_text = text
            for placeholder in placeholders:
                try:
                    decrypted_text = self._decrypt_placeholder(placeholder)
                    if decrypted_text:
                        processed_text = processed_text.replace(placeholder, decrypted_text)
                except Exception as e:
                    logger.error(f"Failed to decrypt placeholder {placeholder}: {e}")
                    continue
            
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
