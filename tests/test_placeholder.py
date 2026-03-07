"""
占位符管理器测试 - 户部负责
"""

import pytest
import tempfile
from pathlib import Path

from ai_security_audit.core.placeholder import PlaceholderManager, PlaceholderEntry, is_placeholder
from ai_security_audit.core.encryptor import EncryptedBlob


class TestPlaceholderManager:
    """测试占位符管理器"""
    
    @pytest.fixture
    def manager(self):
        """创建临时管理器"""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage_path = Path(tmpdir) / 'placeholders.json'
            yield PlaceholderManager(storage_path)
    
    @pytest.fixture
    def sample_blob(self):
        """创建示例加密数据"""
        return EncryptedBlob(
            encrypted_key=b'test_key',
            ciphertext=b'test_cipher',
            nonce=b'test_nonce',
            tag=b'test_tag',
            algorithm='RSA-4096+AES-256-GCM',
            key_fingerprint='test_fp'
        )
    
    def test_create_placeholder(self, manager, sample_blob):
        """测试创建占位符"""
        placeholder = manager.create_placeholder(sample_blob, 'api_key')
        
        assert placeholder.startswith('<SECURE_')
        assert placeholder.endswith('>')
        assert 'APIKEY' in placeholder
    
    def test_resolve_placeholder(self, manager, sample_blob):
        """测试解析占位符"""
        placeholder = manager.create_placeholder(sample_blob, 'api_key')
        
        resolved = manager.resolve_placeholder(placeholder)
        assert resolved is not None
        assert resolved.key_fingerprint == sample_blob.key_fingerprint
    
    def test_placeholder_not_found(self, manager):
        """测试不存在的占位符"""
        resolved = manager.resolve_placeholder("<SECURE_APIKEY_NONEXIST>")
        assert resolved is None
    
    def test_get_placeholder_info(self, manager, sample_blob):
        """测试获取占位符信息"""
        placeholder = manager.create_placeholder(
            sample_blob, 'api_key', metadata={'test': 'value'}
        )
        
        info = manager.get_placeholder_info(placeholder)
        assert info is not None
        assert info['match_type'] == 'api_key'
        assert info['access_count'] == 0
    
    def test_list_placeholders(self, manager, sample_blob):
        """测试列出占位符"""
        manager.create_placeholder(sample_blob, 'api_key')
        manager.create_placeholder(sample_blob, 'password')
        
        all_placeholders = manager.list_placeholders()
        assert len(all_placeholders) == 2
        
        api_placeholders = manager.list_placeholders('api_key')
        assert len(api_placeholders) == 1
    
    def test_delete_placeholder(self, manager, sample_blob):
        """测试删除占位符"""
        placeholder = manager.create_placeholder(sample_blob, 'api_key')
        
        assert manager.delete_placeholder(placeholder) is True
        assert manager.resolve_placeholder(placeholder) is None
        assert manager.delete_placeholder(placeholder) is False
    
    def test_extract_placeholders_from_text(self, manager):
        """测试从文本提取占位符"""
        text = "这里有一个占位符 <SECURE_APIKEY_ABC123> 和另一个 <SECURE_SECRET_XYZ789>"
        placeholders = manager.extract_placeholders_from_text(text)
        
        assert len(placeholders) == 2
        assert '<SECURE_APIKEY_ABC123>' in placeholders
        assert '<SECURE_SECRET_XYZ789>' in placeholders
    
    def test_get_stats(self, manager, sample_blob):
        """测试获取统计信息"""
        manager.create_placeholder(sample_blob, 'api_key')
        manager.create_placeholder(sample_blob, 'api_key')
        manager.create_placeholder(sample_blob, 'password')
        
        stats = manager.get_stats()
        assert stats['total_placeholders'] == 3
        assert stats['type_distribution']['api_key'] == 2
        assert stats['type_distribution']['password'] == 1


class TestIsPlaceholder:
    """测试占位符识别函数"""
    
    def test_valid_placeholder(self):
        """测试有效占位符"""
        assert is_placeholder("<SECURE_APIKEY_ABC123>") is True
        assert is_placeholder("<SECURE_SECRET_XYZ789ABCDEF>") is True
    
    def test_invalid_placeholder(self):
        """测试无效占位符"""
        assert is_placeholder("SECURE_APIKEY_ABC123") is False
        assert is_placeholder("<SECURE_APIKEY_ABC123") is False
        assert is_placeholder("<INVALID>") is False
        assert is_placeholder("普通文本") is False
