"""
审计日志模块 - 吏部负责
记录所有敏感操作，可追溯可审计
"""

import json
import hashlib
import logging
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from typing import Dict, Any, Optional, List
from pathlib import Path
import threading

from ai_security_audit.core.detector import MatchResult

logger = logging.getLogger(__name__)


class AuditEventType(Enum):
    """审计事件类型"""
    DETECTION = "detection"           # 检测到敏感信息
    ENCRYPTION = "encryption"         # 加密操作
    DECRYPTION = "decryption"         # 解密操作
    ACCESS = "access"                 # 访问敏感信息
    PLACEHOLDER_CREATED = "placeholder_created"  # 创建占位符
    PLACEHOLDER_RESOLVED = "placeholder_resolved"  # 解析占位符
    CONFIG_CHANGE = "config_change"   # 配置变更
    ERROR = "error"                   # 错误事件


@dataclass
class AuditEvent:
    """审计事件"""
    event_id: str
    event_type: str
    timestamp: str
    placeholder: Optional[str]
    match_type: Optional[str]
    details: Dict[str, Any]
    actor: str  # 执行者标识（系统/用户/插件）
    success: bool
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return asdict(self)
    
    @classmethod
    def create(
        cls,
        event_type: AuditEventType,
        placeholder: Optional[str] = None,
        match_type: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        actor: str = "system",
        success: bool = True,
        error_message: Optional[str] = None
    ) -> 'AuditEvent':
        """创建审计事件"""
        # 生成唯一事件ID
        timestamp = datetime.now().isoformat()
        event_data = f"{timestamp}:{event_type.value}:{actor}"
        event_id = hashlib.sha256(event_data.encode()).hexdigest()[:16]
        
        return cls(
            event_id=event_id,
            event_type=event_type.value,
            timestamp=timestamp,
            placeholder=placeholder,
            match_type=match_type,
            details=details or {},
            actor=actor,
            success=success,
            error_message=error_message
        )


class SecurityAuditor:
    """
    安全审计器
    
    职责：
    1. 记录所有敏感操作
    2. 提供审计日志查询
    3. 生成统计报告
    4. 确保日志完整性和不可篡改性
    """
    
    def __init__(
        self,
        log_path: Optional[Path] = None,
        max_file_size: int = 10 * 1024 * 1024,  # 10MB
        max_backup_files: int = 5
    ):
        """
        初始化审计器
        
        Args:
            log_path: 审计日志文件路径
            max_file_size: 单个日志文件最大大小
            max_backup_files: 保留的备份文件数量
        """
        if log_path is None:
            log_path = Path.home() / '.openclaw' / 'security' / 'audit.log'
        
        self._log_path = Path(log_path)
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        
        self._max_file_size = max_file_size
        self._max_backup_files = max_backup_files
        self._lock = threading.Lock()
        
        # 初始化日志文件
        self._init_log_file()
    
    def _init_log_file(self) -> None:
        """初始化日志文件"""
        if not self._log_path.exists():
            self._log_path.touch()
            self._log_path.chmod(0o600)  # 只有所有者可读写
    
    def _rotate_log_if_needed(self) -> None:
        """轮转日志文件（如果超过大小限制）"""
        if not self._log_path.exists():
            return
        
        if self._log_path.stat().st_size < self._max_file_size:
            return
        
        # 轮转：将现有日志重命名为 .1, .2 等
        for i in range(self._max_backup_files - 1, 0, -1):
            older = self._log_path.with_suffix(f'.{i}')
            newer = self._log_path.with_suffix(f'.{i-1}' if i > 1 else '')
            if i == 1:
                newer = self._log_path
            
            if older.exists():
                older.unlink()
            if newer.exists():
                newer.rename(older)
        
        # 创建新日志文件
        self._log_path.touch()
        self._log_path.chmod(0o600)
    
    def _write_event(self, event: AuditEvent) -> None:
        """写入事件到日志"""
        with self._lock:
            self._rotate_log_if_needed()
            
            # 追加写入JSON行
            with open(self._log_path, 'a', encoding='utf-8') as f:
                json_line = json.dumps(event.to_dict(), ensure_ascii=False)
                f.write(json_line + '\n')
    
    def log_detection(
        self,
        match: MatchResult,
        placeholder: str,
        actor: str = "detector"
    ) -> None:
        """
        记录检测到敏感信息
        
        Args:
            match: 匹配结果
            placeholder: 生成的占位符
            actor: 执行者
        """
        event = AuditEvent.create(
            event_type=AuditEventType.DETECTION,
            placeholder=placeholder,
            match_type=match.match_type,
            details={
                'matched_text_hash': hashlib.sha256(
                    match.matched_text.encode()
                ).hexdigest()[:16],
                'confidence': match.confidence,
                'start_pos': match.start_pos,
                'end_pos': match.end_pos,
                'metadata': match.metadata
            },
            actor=actor,
            success=True
        )
        
        self._write_event(event)
        logger.debug(f"Logged detection: {placeholder}")
    
    def log_encryption(
        self,
        placeholder: str,
        match_type: str,
        key_fingerprint: str,
        actor: str = "encryptor"
    ) -> None:
        """记录加密操作"""
        event = AuditEvent.create(
            event_type=AuditEventType.ENCRYPTION,
            placeholder=placeholder,
            match_type=match_type,
            details={
                'key_fingerprint': key_fingerprint,
                'algorithm': 'RSA-4096+AES-256-GCM'
            },
            actor=actor,
            success=True
        )
        
        self._write_event(event)
        logger.debug(f"Logged encryption: {placeholder}")
    
    def log_decryption(
        self,
        placeholder: str,
        match_type: Optional[str] = None,
        actor: str = "user",
        success: bool = True,
        error_message: Optional[str] = None
    ) -> None:
        """记录解密操作"""
        event = AuditEvent.create(
            event_type=AuditEventType.DECRYPTION,
            placeholder=placeholder,
            match_type=match_type,
            details={},
            actor=actor,
            success=success,
            error_message=error_message
        )
        
        self._write_event(event)
        
        if success:
            logger.info(f"Logged decryption: {placeholder} by {actor}")
        else:
            logger.warning(f"Logged failed decryption: {placeholder} by {actor}")
    
    def log_access(
        self,
        placeholder: str,
        action: str,
        actor: str = "user",
        success: bool = True
    ) -> None:
        """记录访问敏感信息"""
        event = AuditEvent.create(
            event_type=AuditEventType.ACCESS,
            placeholder=placeholder,
            details={'action': action},
            actor=actor,
            success=success
        )
        
        self._write_event(event)
        logger.debug(f"Logged access: {placeholder}, action: {action}")
    
    def log_placeholder_created(
        self,
        placeholder: str,
        match_type: str,
        actor: str = "placeholder_manager"
    ) -> None:
        """记录占位符创建"""
        event = AuditEvent.create(
            event_type=AuditEventType.PLACEHOLDER_CREATED,
            placeholder=placeholder,
            match_type=match_type,
            actor=actor,
            success=True
        )
        
        self._write_event(event)
        logger.debug(f"Logged placeholder creation: {placeholder}")
    
    def log_placeholder_resolved(
        self,
        placeholder: str,
        match_type: Optional[str] = None,
        actor: str = "placeholder_manager"
    ) -> None:
        """记录占位符解析"""
        event = AuditEvent.create(
            event_type=AuditEventType.PLACEHOLDER_RESOLVED,
            placeholder=placeholder,
            match_type=match_type,
            actor=actor,
            success=True
        )
        
        self._write_event(event)
        logger.debug(f"Logged placeholder resolution: {placeholder}")
    
    def log_config_change(
        self,
        config_key: str,
        old_value: Optional[str],
        new_value: Optional[str],
        actor: str = "user"
    ) -> None:
        """记录配置变更"""
        # 对值进行脱敏处理
        def mask_value(v: Optional[str]) -> Optional[str]:
            if v is None:
                return None
            if len(v) <= 8:
                return "****"
            return v[:4] + "****" + v[-4:]
        
        event = AuditEvent.create(
            event_type=AuditEventType.CONFIG_CHANGE,
            details={
                'config_key': config_key,
                'old_value': mask_value(old_value),
                'new_value': mask_value(new_value)
            },
            actor=actor,
            success=True
        )
        
        self._write_event(event)
        logger.info(f"Logged config change: {config_key}")
    
    def log_error(
        self,
        error_type: str,
        error_message: str,
        details: Optional[Dict[str, Any]] = None,
        actor: str = "system"
    ) -> None:
        """记录错误事件"""
        event = AuditEvent.create(
            event_type=AuditEventType.ERROR,
            details={
                'error_type': error_type,
                **(details or {})
            },
            actor=actor,
            success=False,
            error_message=error_message
        )
        
        self._write_event(event)
        logger.error(f"Logged error: {error_type} - {error_message}")
    
    def get_logs(
        self,
        event_type: Optional[str] = None,
        placeholder: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        查询审计日志
        
        Args:
            event_type: 事件类型过滤
            placeholder: 占位符过滤
            start_time: 开始时间（ISO格式）
            end_time: 结束时间（ISO格式）
            limit: 返回的最大条数
            
        Returns:
            审计事件列表
        """
        logs: List[Dict[str, Any]] = []
        
        # 读取当前日志文件和备份文件
        log_files = [self._log_path]
        for i in range(1, self._max_backup_files + 1):
            backup = self._log_path.with_suffix(f'.{i}')
            if backup.exists():
                log_files.append(backup)
        
        for log_file in log_files:
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        
                        try:
                            event = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        
                        # 应用过滤条件
                        if event_type and event.get('event_type') != event_type:
                            continue
                        if placeholder and event.get('placeholder') != placeholder:
                            continue
                        if start_time and event.get('timestamp', '') < start_time:
                            continue
                        if end_time and event.get('timestamp', '') > end_time:
                            continue
                        
                        logs.append(event)
                        
                        if len(logs) >= limit:
                            break
                            
            except Exception as e:
                logger.error(f"Failed to read log file {log_file}: {e}")
        
        # 按时间排序
        logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        return logs[:limit]
    
    def get_stats(self) -> Dict[str, Any]:
        """获取审计统计信息"""
        stats = {
            'total_events': 0,
            'events_by_type': {},
            'unique_placeholders': set(),
            'log_file_size': 0,
            'log_file_path': str(self._log_path)
        }
        
        if self._log_path.exists():
            stats['log_file_size'] = self._log_path.stat().st_size
        
        log_files = [self._log_path]
        for i in range(1, self._max_backup_files + 1):
            backup = self._log_path.with_suffix(f'.{i}')
            if backup.exists():
                log_files.append(backup)
                stats['log_file_size'] += backup.stat().st_size
        
        for log_file in log_files:
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        
                        try:
                            event = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        
                        stats['total_events'] += 1
                        
                        event_type = event.get('event_type', 'unknown')
                        stats['events_by_type'][event_type] = \
                            stats['events_by_type'].get(event_type, 0) + 1
                        
                        placeholder = event.get('placeholder')
                        if placeholder:
                            stats['unique_placeholders'].add(placeholder)
                            
            except Exception as e:
                logger.error(f"Failed to read log file {log_file}: {e}")
        
        stats['unique_placeholders'] = len(stats['unique_placeholders'])
        
        return stats
    
    def verify_integrity(self) -> bool:
        """
        验证日志完整性
        
        检查所有日志行是否为有效的JSON格式
        
        Returns:
            是否通过完整性验证
        """
        log_files = [self._log_path]
        for i in range(1, self._max_backup_files + 1):
            backup = self._log_path.with_suffix(f'.{i}')
            if backup.exists():
                log_files.append(backup)
        
        for log_file in log_files:
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        line = line.strip()
                        if not line:
                            continue
                        
                        try:
                            event = json.loads(line)
                            # 检查必需字段
                            if 'event_id' not in event or 'timestamp' not in event:
                                logger.error(
                                    f"Integrity check failed: {log_file}:{line_num}"
                                )
                                return False
                        except json.JSONDecodeError:
                            logger.error(
                                f"Integrity check failed: {log_file}:{line_num} - Invalid JSON"
                            )
                            return False
                            
            except Exception as e:
                logger.error(f"Integrity check failed: {log_file} - {e}")
                return False
        
        return True


# 全局审计器实例（用于便捷访问）
default_auditor: Optional[SecurityAuditor] = None


def get_default_auditor() -> SecurityAuditor:
    """获取默认审计器实例"""
    global default_auditor
    if default_auditor is None:
        default_auditor = SecurityAuditor()
    return default_auditor
