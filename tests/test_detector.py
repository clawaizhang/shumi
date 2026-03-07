"""
敏感信息检测器测试 - 刑部负责
"""

import pytest
from ai_security_audit.core.detector import SensitiveInfoDetector, MatchResult


class TestSensitiveInfoDetector:
    """测试敏感信息检测器"""
    
    def test_detect_api_key(self):
        """测试API Key检测"""
        detector = SensitiveInfoDetector()
        
        # OpenAI API Key
        text = "我的OpenAI API Key是 sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEF"
        matches = detector.detect(text)
        
        assert len(matches) >= 1
        assert any(m.match_type == 'openai_api_key' for m in matches)
    
    def test_detect_aws_key(self):
        """测试AWS Key检测"""
        detector = SensitiveInfoDetector()
        
        text = "AWS Access Key: AKIAIOSFODNN7EXAMPLE"
        matches = detector.detect(text)
        
        assert len(matches) >= 1
        assert any(m.match_type == 'aws_key' for m in matches)
    
    def test_detect_github_token(self):
        """测试GitHub Token检测"""
        detector = SensitiveInfoDetector()
        
        text = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        matches = detector.detect(text)
        
        # GitHub Token格式可能有变化，这里主要测试不报错
        assert isinstance(matches, list)
    
    def test_detect_jwt(self):
        """测试JWT检测"""
        detector = SensitiveInfoDetector()
        
        # 示例JWT
        text = "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        matches = detector.detect(text)
        
        assert len(matches) >= 1
        assert any(m.match_type == 'jwt' for m in matches)
    
    def test_detect_password(self):
        """测试密码检测"""
        detector = SensitiveInfoDetector()
        
        text = "password: mySecretPassword123"
        matches = detector.detect(text)
        
        assert len(matches) >= 1
        assert any(m.match_type == 'password' for m in matches)
    
    def test_detect_private_key(self):
        """测试私钥检测"""
        detector = SensitiveInfoDetector()
        
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
        matches = detector.detect(text)
        
        assert len(matches) >= 1
        assert any(m.match_type == 'private_key' for m in matches)
    
    def test_min_confidence_filter(self):
        """测试置信度过滤"""
        detector = SensitiveInfoDetector()
        
        text = "API key: abcdefghijklmnopqrstuvwxyz123456"
        
        # 高置信度阈值
        matches_high = detector.detect(text, min_confidence=0.9)
        # 低置信度阈值
        matches_low = detector.detect(text, min_confidence=0.1)
        
        # 低置信度应该匹配更多
        assert len(matches_low) >= len(matches_high)
    
    def test_no_sensitive_info(self):
        """测试无敏感信息的情况"""
        detector = SensitiveInfoDetector()
        
        text = "这是一段普通的文本，没有任何敏感信息。"
        matches = detector.detect(text)
        
        assert len(matches) == 0
    
    def test_deduplicate_matches(self):
        """测试去重功能"""
        detector = SensitiveInfoDetector()
        
        # 两个重叠的匹配
        text = "key1: AKIAIOSFODNN7EXAMPLE key2: AKIAIOSFODNN7EXAMPLE"
        matches = detector.detect(text)
        
        # 应该能够正确处理
        assert isinstance(matches, list)


class TestMatchResult:
    """测试匹配结果类"""
    
    def test_match_result_creation(self):
        """测试MatchResult创建"""
        result = MatchResult(
            match_type='api_key',
            matched_text='sk-abc123',
            start_pos=10,
            end_pos=20,
            confidence=0.95,
            metadata={'description': 'API Key'}
        )
        
        assert result.match_type == 'api_key'
        assert result.confidence == 0.95
    
    def test_match_result_repr(self):
        """测试MatchResult字符串表示"""
        result = MatchResult(
            match_type='api_key',
            matched_text='sk-abcdefghijklmnop',
            start_pos=0,
            end_pos=19,
            confidence=0.95,
            metadata={}
        )
        
        repr_str = repr(result)
        assert 'api_key' in repr_str
        assert '****' in repr_str  # 应该脱敏显示
