"""
审计日志测试 - 吏部负责
"""

import pytest
import tempfile
from pathlib import Path
from datetime import datetime, timedelta

from ai_security_audit.core.auditor import SecurityAuditor, AuditEvent, AuditEventType
from ai_security_audit.core.detector import MatchResult


class TestSecurityAuditor:
    """测试安全审计器"""
    
    @pytest.fixture
    def auditor(self):
        """创建临时审计器"""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = Path(tmpdir) / 'audit.log'
            yield SecurityAuditor(log_path)
    
    @pytest.fixture
    def sample_match(self):
        """创建示例匹配结果"""
        return MatchResult(
            match_type='api_key',
            matched_text='sk-abc123xyz789',
            start_pos=10,
            end_pos=25,
            confidence=0.95,
            metadata={'description': 'API Key'}
        )
    
    def test_log_detection(self, auditor, sample_match):
        """测试记录检测事件"""
        auditor.log_detection(sample_match, '<SECURE_APIKEY_TEST123>')
        
        logs = auditor.get_logs(event_type='detection')
        assert len(logs) == 1
        assert logs[0]['event_type'] == 'detection'
    
    def test_log_encryption(self, auditor):
        """测试记录加密事件"""
        auditor.log_encryption('<SECURE_APIKEY_TEST>', 'api_key', 'fp123')
        
        logs = auditor.get_logs(event_type='encryption')
        assert len(logs) == 1
    
    def test_log_decryption(self, auditor):
        """测试记录解密事件"""
        auditor.log_decryption('<SECURE_APIKEY_TEST>', actor='user', success=True)
        auditor.log_decryption('<SECURE_APIKEY_TEST2>', actor='user', success=False, error_message='Key not found')
        
        logs = auditor.get_logs(event_type='decryption')
        assert len(logs) == 2
    
    def test_get_logs_with_filter(self, auditor):
        """测试带过滤条件的日志查询"""
        auditor.log_encryption('<SECURE_A>', 'api_key', 'fp1')
        auditor.log_encryption('<SECURE_B>', 'password', 'fp2')
        
        # 按类型过滤
        logs = auditor.get_logs(event_type='encryption')
        assert len(logs) == 2
        
        # 按占位符过滤
        logs = auditor.get_logs(placeholder='<SECURE_A>')
        assert len(logs) == 1
    
    def test_get_stats(self, auditor):
        """测试获取统计信息"""
        auditor.log_encryption('<SECURE_A>', 'api_key', 'fp1')
        auditor.log_encryption('<SECURE_B>', 'password', 'fp2')
        auditor.log_decryption('<SECURE_A>', actor='user')
        
        stats = auditor.get_stats()
        assert stats['total_events'] == 3
        assert stats['events_by_type']['encryption'] == 2
        assert stats['events_by_type']['decryption'] == 1
        assert stats['unique_placeholders'] == 2
    
    def test_verify_integrity(self, auditor):
        """测试日志完整性验证"""
        auditor.log_encryption('<SECURE_TEST>', 'api_key', 'fp1')
        
        assert auditor.verify_integrity() is True
    
    def test_log_config_change(self, auditor):
        """测试记录配置变更"""
        auditor.log_config_change('public_key', '/old/path', '/new/path')
        
        logs = auditor.get_logs(event_type='config_change')
        assert len(logs) == 1
        # 值应该被脱敏
        assert '****' in logs[0]['details']['new_value']


class TestAuditEvent:
    """测试审计事件类"""
    
    def test_create_event(self):
        """测试创建事件"""
        event = AuditEvent.create(
            event_type=AuditEventType.DETECTION,
            placeholder='<SECURE_TEST>',
            match_type='api_key',
            details={'confidence': 0.95},
            actor='test'
        )
        
        assert event.event_type == 'detection'
        assert event.placeholder == '<SECURE_TEST>'
        assert event.success is True
        assert 'event_id' in event.to_dict()
        assert 'timestamp' in event.to_dict()
