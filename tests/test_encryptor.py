"""
加密模块测试 - 兵部负责
"""

import pytest
import tempfile
from pathlib import Path

from ai_security_audit.core.encryptor import (
    LocalEncryptor, LocalDecryptor, EncryptedBlob
)


class TestLocalEncryptor:
    """测试本地加密器"""
    
    @pytest.fixture
    def key_pair(self):
        """生成临时密钥对"""
        with tempfile.TemporaryDirectory() as tmpdir:
            private_key = Path(tmpdir) / 'test_key'
            public_key = Path(tmpdir) / 'test_key.pub'
            
            encryptor = LocalEncryptor()
            encryptor.generate_key_pair(private_key, public_key)
            
            yield {'private': private_key, 'public': public_key}
    
    def test_generate_key_pair(self, key_pair):
        """测试密钥对生成"""
        assert key_pair['private'].exists()
        assert key_pair['public'].exists()
    
    def test_encrypt_decrypt(self, key_pair):
        """测试加密解密流程"""
        # 加密
        encryptor = LocalEncryptor(key_pair['public'])
        plaintext = "这是敏感信息: my-secret-password-123!"
        
        blob = encryptor.encrypt(plaintext)
        
        assert isinstance(blob, EncryptedBlob)
        assert blob.algorithm == 'RSA-4096+AES-256-GCM'
        assert blob.key_fingerprint is not None
        
        # 解密
        decryptor = LocalDecryptor(key_pair['private'])
        decrypted = decryptor.decrypt(blob)
        
        assert decrypted == plaintext
    
    def test_encrypt_bytes(self, key_pair):
        """测试字节加密"""
        encryptor = LocalEncryptor(key_pair['public'])
        data = b"\x00\x01\x02\x03\xff\xfe\xfd\xfc"  # 二进制数据
        
        blob = encryptor.encrypt_bytes(data)
        
        decryptor = LocalDecryptor(key_pair['private'])
        decrypted = decryptor.decrypt_bytes(blob)
        
        assert decrypted == data
    
    def test_blob_serialization(self, key_pair):
        """测试加密数据序列化"""
        encryptor = LocalEncryptor(key_pair['public'])
        plaintext = "test data"
        
        blob = encryptor.encrypt(plaintext)
        
        # 转换为字典
        blob_dict = blob.to_dict()
        assert 'encrypted_key' in blob_dict
        assert 'ciphertext' in blob_dict
        assert 'nonce' in blob_dict
        assert 'tag' in blob_dict
        
        # 从字典恢复
        restored = EncryptedBlob.from_dict(blob_dict)
        assert restored.key_fingerprint == blob.key_fingerprint
        
        # 解密恢复的数据
        decryptor = LocalDecryptor(key_pair['private'])
        decrypted = decryptor.decrypt(restored)
        assert decrypted == plaintext
    
    def test_key_fingerprint(self, key_pair):
        """测试密钥指纹"""
        encryptor = LocalEncryptor(key_pair['public'])
        fingerprint = encryptor.get_key_fingerprint()
        
        assert fingerprint is not None
        assert len(fingerprint) == 16  # SHA256前16个字符
    
    def test_is_ready(self, key_pair):
        """测试就绪状态检查"""
        encryptor = LocalEncryptor()
        assert not encryptor.is_ready()
        
        encryptor.load_public_key(key_pair['public'])
        assert encryptor.is_ready()
    
    def test_encrypt_without_key(self):
        """测试未加载密钥时的加密行为"""
        encryptor = LocalEncryptor()
        
        with pytest.raises(RuntimeError):
            encryptor.encrypt("test")


class TestEncryptedBlob:
    """测试加密数据容器"""
    
    def test_compact_string(self):
        """测试紧凑字符串格式"""
        blob = EncryptedBlob(
            encrypted_key=b'key_data',
            ciphertext=b'cipher_data',
            nonce=b'nonce',
            tag=b'tag',
            algorithm='RSA-4096+AES-256-GCM',
            key_fingerprint='abc123'
        )
        
        compact = blob.to_compact_string()
        assert ':' in compact
        
        # 从紧凑字符串恢复
        restored = EncryptedBlob.from_compact_string(compact)
        assert restored.key_fingerprint == 'abc123'
