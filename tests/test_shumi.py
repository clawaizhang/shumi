"""
单元测试 - 枢密 (Shumi) 核心模块
"""

import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import numpy as np


class TestAISensitiveDetector:
    """AI敏感信息检测器测试"""
    
    @pytest.fixture
    def mock_detector(self):
        """创建Mock检测器"""
        from shumi.core.ai_detector import AISensitiveDetector
        
        # Mock模型和配置
        with patch('shumi.core.ai_detector.SentenceTransformer') as mock_model:
            mock_instance = MagicMock()
            mock_instance.encode.return_value = np.array([[0.1, 0.2, 0.3]])
            mock_model.return_value = mock_instance
            
            # Mock配置文件
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump({
                    'api_keys': [
                        {'chunk_size': 50, 'step_size': 25, 'center': [0.1, 0.2, 0.3], 'threshold': 0.75},
                        {'chunk_size': 100, 'step_size': 50, 'center': [0.2, 0.3, 0.4], 'threshold': 0.75}
                    ]
                }, f)
                config_path = f.name
            
            detector = AISensitiveDetector(config_path)
            yield detector
            
            # 清理
            Path(config_path).unlink()
    
    def test_detect_api_key_in_text(self, mock_detector):
        """测试检测文本中的API Key"""
        text = "我的API Key是 sk-abc123xyz789"
        
        with patch.object(mock_detector, '_encode_chunks') as mock_encode:
            mock_encode.return_value = [
                np.array([0.15, 0.25, 0.35])  # 模拟相似度高的embedding
            ]
            
            results = mock_detector.detect(text)
            
            assert len(results) > 0
            assert results[0]['category'] == 'api_keys'
    
    def test_detect_no_sensitive_info(self, mock_detector):
        """测试无敏感信息的文本"""
        text = "这是一段普通的文本，没有敏感信息"
        
        with patch.object(mock_detector, '_encode_chunks') as mock_encode:
            mock_encode.return_value = [
                np.array([0.9, 0.9, 0.9])  # 模拟相似度低的embedding
            ]
            
            results = mock_detector.detect(text)
            
            assert len(results) == 0
    
    def test_multi_scale_detection(self, mock_detector):
        """测试多尺度检测"""
        text = "短密码: 123456, 长API Key: sk-abcdefghijklmnopqrstuvwxyz123456"
        
        chunks = mock_detector._create_chunks(text)
        
        # 验证生成了多个尺度的chunks
        assert len(chunks) > 0
        # 验证有重叠
        if len(chunks) > 1:
            assert chunks[0]['end'] > chunks[1]['start']  # 有重叠


class TestPlaceholderManager:
    """占位符管理器测试"""
    
    @pytest.fixture
    def manager(self):
        from shumi.core.placeholder import PlaceholderManager
        with tempfile.TemporaryDirectory() as tmpdir:
            yield PlaceholderManager(storage_path=tmpdir)
    
    def test_create_placeholder(self, manager):
        """测试创建占位符"""
        encrypted_data = b"encrypted_blob_data"
        placeholder = manager.create_placeholder(encrypted_data, "api_key")
        
        assert placeholder.startswith("<SECURE_")
        assert placeholder.endswith(">")
        assert "APIKEY" in placeholder
    
    def test_resolve_placeholder(self, manager):
        """测试解析占位符"""
        encrypted_data = b"test_data_12345"
        placeholder = manager.create_placeholder(encrypted_data, "api_key")
        
        resolved = manager.resolve_placeholder(placeholder)
        
        assert resolved == encrypted_data
    
    def test_extract_placeholders_from_text(self, manager):
        """测试从文本中提取占位符"""
        text = "我的Key是 <SECURE_APIKEY_a1b2c3d4> 和 <SECURE_SECRET_e5f6g7h8>"
        
        placeholders = manager.extract_placeholders_from_text(text)
        
        assert len(placeholders) == 2
        assert "<SECURE_APIKEY_a1b2c3d4>" in placeholders
        assert "<SECURE_SECRET_e5f6g7h8>" in placeholders


class TestSecurityAuditor:
    """安全审计器测试"""
    
    @pytest.fixture
    def auditor(self):
        from shumi.core.auditor import SecurityAuditor
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            yield SecurityAuditor(f.name)
    
    def test_log_detection(self, auditor):
        """测试记录检测日志"""
        mock_match = Mock()
        mock_match.matched_text = "sk-test123"
        mock_match.match_type = "api_key"
        mock_match.confidence = 0.95
        
        auditor.log_detection(mock_match, "<SECURE_TEST>", "test_actor")
        
        # 验证日志已记录
        stats = auditor.get_stats()
        assert stats['detection_count'] >= 1
    
    def test_log_encryption(self, auditor):
        """测试记录加密日志"""
        auditor.log_encryption("<SECURE_TEST>", "api_key", "key_fingerprint", "test")
        
        stats = auditor.get_stats()
        assert stats['encryption_count'] >= 1


class TestEncryptor:
    """加密器测试"""
    
    def test_encryption_decryption_roundtrip(self):
        """测试加密解密往返"""
        from shumi.core.encryptor import LocalEncryptor, LocalDecryptor
        
        # 生成测试密钥对
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        
        # 保存到临时文件
        with tempfile.TemporaryDirectory() as tmpdir:
            pub_path = Path(tmpdir) / "test.pub"
            priv_path = Path(tmpdir) / "test.key"
            
            pub_path.write_bytes(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
            priv_path.write_bytes(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )
            
            # 测试加密解密
            encryptor = LocalEncryptor(str(pub_path))
            decryptor = LocalDecryptor(str(priv_path))
            
            plaintext = "我的敏感信息 Secret123!"
            encrypted = encryptor.encrypt(plaintext)
            
            assert encrypted is not None
            assert encrypted != plaintext.encode()
            
            decrypted = decryptor.decrypt(encrypted)
            assert decrypted == plaintext


class TestSecurityAuditHook:
    """安全审计Hook集成测试"""
    
    @pytest.fixture
    def mock_hook(self):
        """创建Mock Hook"""
        from shumi.plugins.openclaw_hook import SecurityAuditHook
        
        with tempfile.TemporaryDirectory() as tmpdir:
            config = {
                'placeholder_storage': tmpdir,
                'chunk_strategy_path': None  # 使用默认
            }
            
            with patch('shumi.plugins.openclaw_hook.AISensitiveDetector'):
                with patch('shumi.plugins.openclaw_hook.LocalEncryptor'):
                    with patch('shumi.plugins.openclaw_hook.LocalDecryptor'):
                        hook = SecurityAuditHook(config)
                        hook._initialized = True
                        hook._ai_detector = Mock()
                        hook._encryptor = Mock()
                        hook._decryptor = Mock()
                        hook._placeholder_manager = Mock()
                        hook._auditor = Mock()
                        
                        yield hook
    
    def test_preprocess_detects_and_encrypts(self, mock_hook):
        """测试预处理检测并加密"""
        from shumi.core.ai_detector import MatchResult
        
        # Mock AI检测结果
        mock_hook._ai_detector.detect.return_value = [
            {
                'text': 'sk-test123',
                'category': 'api_keys',
                'start': 10,
                'end': 20,
                'confidence': 0.95
            }
        ]
        
        # Mock加密结果
        mock_hook._encryptor.encrypt.return_value = b'encrypted_blob'
        mock_hook._placeholder_manager.create_placeholder.return_value = "<SECURE_TEST>"
        
        text = "我的API Key是 sk-test123"
        result = mock_hook.preprocess(text)
        
        # 验证AI检测被调用
        mock_hook._ai_detector.detect.assert_called_once_with(text)
        
        # 验证加密被调用
        mock_hook._encryptor.encrypt.assert_called_once()
        
        # 验证结果包含占位符
        assert "<SECURE_TEST>" in result
    
    def test_postprocess_decrypts(self, mock_hook):
        """测试后处理解密"""
        mock_hook._placeholder_manager.extract_placeholders_from_text.return_value = ["<SECURE_TEST>"]
        mock_hook._placeholder_manager.resolve_placeholder.return_value = b'encrypted_blob'
        mock_hook._decryptor.decrypt.return_value = "sk-test123"
        
        text = "我的Key是 <SECURE_TEST>"
        result = mock_hook.postprocess(text)
        
        # 验证解密被调用
        mock_hook._decryptor.decrypt.assert_called_once()
        
        # 验证占位符被替换
        assert "sk-test123" in result
        assert "<SECURE_TEST>" not in result
    
    def test_preprocess_no_sensitive_info(self, mock_hook):
        """测试无敏感信息的预处理"""
        mock_hook._ai_detector.detect.return_value = []
        
        text = "这是一段普通的文本"
        result = mock_hook.preprocess(text)
        
        # 验证结果未改变
        assert result == text
        
        # 验证加密未被调用
        mock_hook._encryptor.encrypt.assert_not_called()


class TestChunkStrategies:
    """分块策略测试"""
    
    def test_chunk_overlap(self):
        """测试分块重叠"""
        from shumi.core.ai_detector import AISensitiveDetector
        
        text = "a" * 200  # 200个字符
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({'api_keys': [{'chunk_size': 50, 'step_size': 25}]}, f)
            config_path = f.name
        
        try:
            with patch('shumi.core.ai_detector.SentenceTransformer'):
                detector = AISensitiveDetector(config_path)
                chunks = detector._create_chunks(text)
                
                # 验证有重叠
                if len(chunks) >= 2:
                    # 第二个块的起始应该小于第一个块的结束（有重叠）
                    assert chunks[1]['start'] < chunks[0]['end']
        finally:
            Path(config_path).unlink()


# 运行测试
if __name__ == '__main__':
    pytest.main([__file__, '-v'])
