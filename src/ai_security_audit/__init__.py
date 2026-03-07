"""AI安全审计插件"""

__version__ = "0.1.0"
__author__ = "OpenClaw Security Team"

from ai_security_audit.core.detector import SensitiveInfoDetector, MatchResult
from ai_security_audit.core.encryptor import LocalEncryptor, LocalDecryptor, EncryptedBlob
from ai_security_audit.core.placeholder import PlaceholderManager, is_placeholder
from ai_security_audit.core.auditor import SecurityAuditor

__all__ = [
    'SensitiveInfoDetector',
    'MatchResult',
    'LocalEncryptor',
    'LocalDecryptor',
    'EncryptedBlob',
    'PlaceholderManager',
    'is_placeholder',
    'SecurityAuditor',
]
