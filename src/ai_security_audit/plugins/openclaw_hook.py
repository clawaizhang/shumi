"""
OpenClaw预处理Hook - 户部负责
集成到OpenClaw消息预处理流程
"""

import logging
from typing import Optional, Dict, Any, List
from pathlib import Path

from ai_security_audit.core.detector import SensitiveInfoDetector, MatchResult
from ai_security_audit.core.encryptor import LocalEncryptor
from ai_security_audit.core.placeholder import PlaceholderManager
from ai_security_audit.core.auditor import SecurityAuditor, get_default_auditor

logger = logging.getLogger(__name__)


class SecurityAuditHook:
    """
    OpenClaw安全审计Hook
    
    功能：
    1. 拦截所有发往AI的消息
    2. 检测敏感信息
    3. 加密并替换为占位符
    4. 记录审计日志
    
    使用方式：
    在OpenClaw配置中添加：
    preprocessors:
      - ai_security_audit.plugins.openclaw_hook:SecurityAuditHook
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        初始化Hook
        
        Args:
            config: 配置字典，包含：
                - public_key_path: SSH公钥路径
                - min_confidence: 最低检测置信度（默认0.5）
                - enabled_types: 启用的检测类型列表
                - placeholder_storage: 占位符存储路径
                - audit_log_path: 审计日志路径
        """
        self._config = config or {}
        self._initialized = False
        
        # 组件
        self._detector: Optional[SensitiveInfoDetector] = None
        self._encryptor: Optional[LocalEncryptor] = None
        self._placeholder_manager: Optional[PlaceholderManager] = None
        self._auditor: Optional[SecurityAuditor] = None
        
        # 配置
        self._min_confidence = self._config.get('min_confidence', 0.5)
        self._enabled_types = self._config.get('enabled_types')
        
        self._init_components()
    
    def _init_components(self) -> None:
        """初始化组件"""
        try:
            # 初始化检测器
            self._detector = SensitiveInfoDetector()
            
            # 初始化加密器（需要公钥）
            public_key_path = self._config.get('public_key_path')
            if public_key_path:
                self._encryptor = LocalEncryptor(public_key_path)
                logger.info(f"Loaded public key from: {public_key_path}")
            else:
                # 尝试默认路径
                default_paths = [
                    Path.home() / '.ssh' / 'id_rsa.pub',
                    Path.home() / '.ssh' / 'id_ed25519.pub',
                ]
                for path in default_paths:
                    if path.exists():
                        self._encryptor = LocalEncryptor(path)
                        logger.info(f"Loaded public key from default path: {path}")
                        break
            
            # 初始化占位符管理器
            placeholder_storage = self._config.get('placeholder_storage')
            self._placeholder_manager = PlaceholderManager(placeholder_storage)
            
            # 初始化审计器
            audit_log_path = self._config.get('audit_log_path')
            if audit_log_path:
                self._auditor = SecurityAuditor(audit_log_path)
            else:
                self._auditor = get_default_auditor()
            
            self._initialized = True
            logger.info("SecurityAuditHook initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize SecurityAuditHook: {e}")
            self._initialized = False
    
    def process(self, text: str, context: Optional[Dict[str, Any]] = None) -> str:
        """
        处理输入文本
        
        这是OpenClaw预处理Hook的主入口
        
        Args:
            text: 用户输入文本
            context: 上下文信息
            
        Returns:
            处理后的文本（敏感信息已替换为占位符）
        """
        if not self._initialized:
            logger.warning("SecurityAuditHook not initialized, skipping processing")
            return text
        
        if not self._encryptor or not self._encryptor.is_ready():
            logger.warning("Encryptor not ready, skipping processing")
            return text
        
        try:
            # 检测敏感信息
            matches = self._detector.detect(text, self._min_confidence)
            
            if not matches:
                return text
            
            logger.info(f"Detected {len(matches)} sensitive items")
            
            # 处理匹配项（从后往前，避免位置偏移）
            processed_text = text
            for match in sorted(matches, key=lambda m: m.start_pos, reverse=True):
                try:
                    placeholder = self._process_match(match)
                    if placeholder:
                        # 替换文本
                        processed_text = (
                            processed_text[:match.start_pos] +
                            placeholder +
                            processed_text[match.end_pos:]
                        )
                except Exception as e:
                    logger.error(f"Failed to process match: {e}")
                    continue
            
            return processed_text
            
        except Exception as e:
            logger.error(f"Error during text processing: {e}")
            # 发生错误时返回原始文本（避免阻断用户）
            return text
    
    def _process_match(self, match: MatchResult) -> Optional[str]:
        """
        处理单个匹配项
        
        Args:
            match: 匹配结果
            
        Returns:
            占位符字符串，失败返回None
        """
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
        self._auditor.log_detection(match, placeholder, actor="openclaw_hook")
        self._auditor.log_encryption(
            placeholder,
            match.match_type,
            self._encryptor.get_key_fingerprint() or 'unknown',
            actor="openclaw_hook"
        )
        self._auditor.log_placeholder_created(
            placeholder,
            match.match_type,
            actor="openclaw_hook"
        )
        
        return placeholder
    
    def get_stats(self) -> Dict[str, Any]:
        """获取处理统计信息"""
        stats = {
            'initialized': self._initialized,
            'detector_ready': self._detector is not None,
            'encryptor_ready': self._encryptor is not None and self._encryptor.is_ready(),
            'placeholder_manager_ready': self._placeholder_manager is not None,
            'auditor_ready': self._auditor is not None,
        }
        
        if self._placeholder_manager:
            stats['placeholder_stats'] = self._placeholder_manager.get_stats()
        
        if self._auditor:
            stats['audit_stats'] = self._auditor.get_stats()
        
        return stats
    
    def health_check(self) -> Dict[str, Any]:
        """健康检查"""
        checks = {
            'initialized': self._initialized,
            'detector': self._detector is not None,
            'encryptor': self._encryptor is not None and self._encryptor.is_ready(),
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
class SecurityAuditPlugin:
    """
    OpenClaw插件接口
    
    实现了OpenClaw预处理器插件标准接口
    """
    
    def __init__(self):
        self._hook: Optional[SecurityAuditHook] = None
    
    def initialize(self, config: Dict[str, Any]) -> None:
        """初始化插件"""
        self._hook = SecurityAuditHook(config)
    
    def preprocess(self, text: str, context: Optional[Dict[str, Any]] = None) -> str:
        """
        预处理消息
        
        这是OpenClaw调用的主方法
        """
        if self._hook is None:
            logger.error("Plugin not initialized")
            return text
        
        return self._hook.process(text, context)
    
    def shutdown(self) -> None:
        """关闭插件"""
        logger.info("SecurityAuditPlugin shutdown")


# 便捷函数：创建默认Hook实例
def create_hook(config_path: Optional[Path] = None) -> SecurityAuditHook:
    """
    创建安全审计Hook实例
    
    Args:
        config_path: 配置文件路径
        
    Returns:
        SecurityAuditHook实例
    """
    config = {}
    
    if config_path and config_path.exists():
        try:
            import yaml
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"Failed to load config: {e}")
    
    return SecurityAuditHook(config)
