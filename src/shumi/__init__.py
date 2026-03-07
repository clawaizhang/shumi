"""枢密 - AI机密信息管理插件"""

__version__ = "0.2.0"
__author__ = "OpenClaw Security Team"

from shumi.core.ai_detector import AISensitiveDetector, MatchResult
from shumi.core.encryptor import LocalEncryptor, LocalDecryptor, EncryptedBlob
from shumi.core.placeholder import PlaceholderManager, is_placeholder
from shumi.core.auditor import SecurityAuditor
from shumi.core.notifier import ShumiNotifier

__all__ = [
    'AISensitiveDetector',
    'MatchResult',
    'LocalEncryptor',
    'LocalDecryptor',
    'EncryptedBlob',
    'PlaceholderManager',
    'is_placeholder',
    'SecurityAuditor',
    'ShumiNotifier',
]
