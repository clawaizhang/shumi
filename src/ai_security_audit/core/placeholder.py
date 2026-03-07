"""
占位符管理模块 - 户部负责
管理敏感信息到占位符的映射关系
"""

import json
import hashlib
import re
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, Optional, List, Any
from pathlib import Path
import threading
import logging

from ai_security_audit.core.encryptor import EncryptedBlob

logger = logging.getLogger(__name__)


@dataclass
class PlaceholderEntry:
    """占位符条目"""
    placeholder: str           # 占位符标识
    encrypted_data: dict       # 加密数据（字典格式）
    match_type: str            # 敏感信息类型
    created_at: str            # 创建时间
    access_count: int          # 访问次数
    last_accessed: Optional[str] = None  # 最后访问时间
    metadata: Dict[str, Any] = None      # 额外元数据
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class PlaceholderManager:
    """
    占位符管理器
    
    占位符格式: <SECURE_[TYPE]_[HASH]>
    例: <SECURE_APIKEY_a1b2c3d4>
    
    职责：
    1. 为加密数据创建唯一占位符
    2. 管理占位符到加密数据的映射
    3. 持久化存储映射关系
    4. 提供占位符解析功能
    """
    
    PLACEHOLDER_PATTERN = re.compile(r'<SECURE_([A-Z_]+)_([a-f0-9]{8,16})>')
    
    def __init__(self, storage_path: Optional[Path] = None):
        """
        初始化占位符管理器
        
        Args:
            storage_path: 映射表存储路径
        """
        if storage_path is None:
            storage_path = Path.home() / '.openclaw' / 'security' / 'placeholders.json'
        
        self._storage_path = Path(storage_path)
        self._storage_path.parent.mkdir(parents=True, exist_ok=True)
        
        self._placeholders: Dict[str, PlaceholderEntry] = {}
        self._lock = threading.RLock()
        
        self._load_storage()
    
    def _load_storage(self) -> None:
        """从文件加载映射表"""
        if not self._storage_path.exists():
            return
        
        try:
            with open(self._storage_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for placeholder, entry_data in data.items():
                self._placeholders[placeholder] = PlaceholderEntry(**entry_data)
            
            logger.info(f"Loaded {len(self._placeholders)} placeholder mappings")
            
        except Exception as e:
            logger.error(f"Failed to load placeholder storage: {e}")
    
    def _save_storage(self) -> None:
        """保存映射表到文件"""
        try:
            # 转换为可序列化的字典
            data = {}
            for placeholder, entry in self._placeholders.items():
                entry_dict = asdict(entry)
                data[placeholder] = entry_dict
            
            # 原子写入
            temp_path = self._storage_path.with_suffix('.tmp')
            with open(temp_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            temp_path.replace(self._storage_path)
            
            # 设置权限（只有所有者可读）
            self._storage_path.chmod(0o600)
            
        except Exception as e:
            logger.error(f"Failed to save placeholder storage: {e}")
    
    def create_placeholder(self, encrypted_blob: EncryptedBlob, 
                          match_type: str,
                          metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        为加密数据创建占位符
        
        Args:
            encrypted_blob: 加密数据
            match_type: 敏感信息类型
            metadata: 额外元数据
            
        Returns:
            占位符字符串
        """
        with self._lock:
            # 生成基于内容的唯一哈希（用于识别相同内容的重复加密）
            content_hash = self._compute_hash(encrypted_blob)
            
            # 构建占位符
            type_tag = self._sanitize_type(match_type)
            placeholder = f"<SECURE_{type_tag}_{content_hash}>"
            
            # 检查是否已存在
            if placeholder in self._placeholders:
                logger.debug(f"Placeholder already exists: {placeholder}")
                return placeholder
            
            # 创建条目
            entry = PlaceholderEntry(
                placeholder=placeholder,
                encrypted_data=encrypted_blob.to_dict(),
                match_type=match_type,
                created_at=datetime.now().isoformat(),
                access_count=0,
                metadata=metadata or {}
            )
            
            self._placeholders[placeholder] = entry
            self._save_storage()
            
            logger.info(f"Created placeholder: {placeholder} for type: {match_type}")
            
            return placeholder
    
    def resolve_placeholder(self, placeholder: str) -> Optional[EncryptedBlob]:
        """
        解析占位符，返回加密数据
        
        Args:
            placeholder: 占位符字符串
            
        Returns:
            加密数据，如果不存在返回None
        """
        with self._lock:
            entry = self._placeholders.get(placeholder)
            
            if entry is None:
                logger.warning(f"Placeholder not found: {placeholder}")
                return None
            
            # 更新访问统计
            entry.access_count += 1
            entry.last_accessed = datetime.now().isoformat()
            self._save_storage()
            
            logger.info(f"Resolved placeholder: {placeholder} (access count: {entry.access_count})")
            
            return EncryptedBlob.from_dict(entry.encrypted_data)
    
    def get_placeholder_info(self, placeholder: str) -> Optional[Dict[str, Any]]:
        """
        获取占位符信息（不含加密数据）
        
        Args:
            placeholder: 占位符字符串
            
        Returns:
            占位符信息字典
        """
        with self._lock:
            entry = self._placeholders.get(placeholder)
            
            if entry is None:
                return None
            
            return {
                'placeholder': entry.placeholder,
                'match_type': entry.match_type,
                'created_at': entry.created_at,
                'access_count': entry.access_count,
                'last_accessed': entry.last_accessed,
                'metadata': entry.metadata
            }
    
    def delete_placeholder(self, placeholder: str) -> bool:
        """
        删除占位符
        
        Args:
            placeholder: 占位符字符串
            
        Returns:
            是否成功删除
        """
        with self._lock:
            if placeholder not in self._placeholders:
                return False
            
            del self._placeholders[placeholder]
            self._save_storage()
            
            logger.info(f"Deleted placeholder: {placeholder}")
            
            return True
    
    def list_placeholders(self, match_type: Optional[str] = None) -> List[str]:
        """
        列出所有占位符
        
        Args:
            match_type: 按类型过滤（可选）
            
        Returns:
            占位符列表
        """
        with self._lock:
            if match_type:
                return [
                    p for p, e in self._placeholders.items()
                    if e.match_type == match_type
                ]
            return list(self._placeholders.keys())
    
    def extract_placeholders_from_text(self, text: str) -> List[str]:
        """
        从文本中提取所有占位符
        
        Args:
            text: 待扫描文本
            
        Returns:
            占位符列表
        """
        matches = self.PLACEHOLDER_PATTERN.findall(text)
        return [f"<SECURE_{m[0]}_{m[1]}>" for m in matches]
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        with self._lock:
            type_counts: Dict[str, int] = {}
            total_accesses = 0
            
            for entry in self._placeholders.values():
                type_counts[entry.match_type] = type_counts.get(entry.match_type, 0) + 1
                total_accesses += entry.access_count
            
            return {
                'total_placeholders': len(self._placeholders),
                'type_distribution': type_counts,
                'total_accesses': total_accesses,
                'storage_path': str(self._storage_path)
            }
    
    def _compute_hash(self, encrypted_blob: EncryptedBlob) -> str:
        """
        计算加密数据的短哈希（用于占位符标识）
        
        使用密钥指纹+密文前32字节的SHA256哈希
        """
        data = (
            encrypted_blob.key_fingerprint +
            base64.b64encode(encrypted_blob.ciphertext[:32]).decode('ascii')
        )
        full_hash = hashlib.sha256(data.encode()).hexdigest()
        return full_hash[:12]  # 取前12个字符作为短哈希
    
    def _sanitize_type(self, match_type: str) -> str:
        """将匹配类型转换为合法的占位符标签"""
        # 转换为大写，替换特殊字符
        sanitized = re.sub(r'[^a-zA-Z0-9_]', '_', match_type.upper())
        # 限制长度
        return sanitized[:20]
    
    def cleanup_expired(self, max_age_days: int = 90) -> int:
        """
        清理过期的占位符
        
        Args:
            max_age_days: 最大保留天数
            
        Returns:
            清理的数量
        """
        from datetime import timedelta
        
        with self._lock:
            cutoff = datetime.now() - timedelta(days=max_age_days)
            to_delete = []
            
            for placeholder, entry in self._placeholders.items():
                created = datetime.fromisoformat(entry.created_at)
                if created < cutoff:
                    to_delete.append(placeholder)
            
            for placeholder in to_delete:
                del self._placeholders[placeholder]
            
            if to_delete:
                self._save_storage()
            
            logger.info(f"Cleaned up {len(to_delete)} expired placeholders")
            
            return len(to_delete)


# 便捷函数
def is_placeholder(text: str) -> bool:
    """检查字符串是否为占位符"""
    return bool(PlaceholderManager.PLACEHOLDER_PATTERN.match(text))
