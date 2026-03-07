"""
敏感信息检测器 - 刑部负责
自动识别API Key、密码、Token、私钥等敏感信息
"""

import re
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Pattern
import logging

logger = logging.getLogger(__name__)


@dataclass
class MatchResult:
    """敏感信息匹配结果"""
    match_type: str
    matched_text: str
    start_pos: int
    end_pos: int
    confidence: float  # 置信度 0-1
    metadata: Dict[str, Any]
    
    def __repr__(self) -> str:
        masked = self.matched_text[:4] + "****" if len(self.matched_text) > 4 else "****"
        return f"MatchResult(type={self.match_type}, text={masked}, confidence={self.confidence:.2f})"


class SensitiveInfoDetector:
    """
    敏感信息检测引擎
    
    支持的检测类型：
    - api_key: 通用API密钥
    - aws_key: AWS Access Key ID
    - aws_secret: AWS Secret Access Key
    - secret: 密码/密钥
    - token: Token/Session
    - jwt: JWT令牌
    - private_key: SSH/SSL私钥
    - github_token: GitHub Personal Access Token
    - slack_token: Slack Token
    - stripe_key: Stripe API Key
    - credit_card: 信用卡号
    """
    
    # 敏感信息正则模式库
    PATTERNS: Dict[str, Dict[str, Any]] = {
        # AWS凭证
        'aws_key': {
            'pattern': r'AKIA[0-9A-Z]{16}',
            'confidence': 0.95,
            'description': 'AWS Access Key ID'
        },
        'aws_secret': {
            'pattern': r'[0-9a-zA-Z/+]{40}',
            'confidence': 0.7,
            'description': 'AWS Secret Access Key',
            'context': ['aws', 'secret', 'access']
        },
        
        # API Keys
        'openai_api_key': {
            'pattern': r'sk-[a-zA-Z0-9]{48}',
            'confidence': 0.98,
            'description': 'OpenAI API Key'
        },
        'anthropic_api_key': {
            'pattern': r'sk-ant-[a-zA-Z0-9_-]{32,}',
            'confidence': 0.98,
            'description': 'Anthropic API Key'
        },
        'google_api_key': {
            'pattern': r'AIza[0-9A-Za-z_-]{35}',
            'confidence': 0.95,
            'description': 'Google API Key'
        },
        'generic_api_key': {
            'pattern': r'[a-zA-Z0-9_-]{32,64}',
            'confidence': 0.5,
            'description': 'Generic API Key',
            'context': ['api', 'key', 'token', 'secret']
        },
        
        # GitHub Tokens
        'github_token': {
            'pattern': r'gh[pousr]_[A-Za-z0-9_]{36,}',
            'confidence': 0.98,
            'description': 'GitHub Personal Access Token'
        },
        'github_oauth': {
            'pattern': r'[0-9a-f]{40}',
            'confidence': 0.6,
            'description': 'GitHub OAuth Token',
            'context': ['github', 'oauth']
        },
        
        # Slack Tokens
        'slack_token': {
            'pattern': r'xox[baprs]-[0-9a-zA-Z-]+',
            'confidence': 0.95,
            'description': 'Slack Token'
        },
        'slack_webhook': {
            'pattern': r'https://hooks\.slack\.com/services/[A-Z0-9/]+',
            'confidence': 0.95,
            'description': 'Slack Webhook URL'
        },
        
        # Stripe Keys
        'stripe_live_key': {
            'pattern': r'sk_live_[0-9a-zA-Z]{24,}',
            'confidence': 0.98,
            'description': 'Stripe Live Secret Key'
        },
        'stripe_test_key': {
            'pattern': r'sk_test_[0-9a-zA-Z]{24,}',
            'confidence': 0.98,
            'description': 'Stripe Test Secret Key'
        },
        
        # JWT
        'jwt': {
            'pattern': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
            'confidence': 0.9,
            'description': 'JSON Web Token'
        },
        
        # 私钥
        'private_key': {
            'pattern': r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            'confidence': 0.99,
            'description': 'Private Key'
        },
        'ssh_private_key': {
            'pattern': r'-----BEGIN OPENSSH PRIVATE KEY-----',
            'confidence': 0.99,
            'description': 'SSH Private Key'
        },
        
        # 密码/Secret (带关键词)
        'password': {
            'pattern': r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?([^"\'\s]{8,})',
            'confidence': 0.85,
            'description': 'Password',
            'group': 2
        },
        'secret': {
            'pattern': r'(?i)(secret|api_secret|client_secret)\s*[=:]\s*["\']?([^"\'\s]{8,})',
            'confidence': 0.85,
            'description': 'Secret',
            'group': 2
        },
        'token_kv': {
            'pattern': r'(?i)(token|access_token|refresh_token)\s*[=:]\s*["\']?([^"\'\s]{8,})',
            'confidence': 0.8,
            'description': 'Token (Key-Value)',
            'group': 2
        },
        
        # 数据库连接字符串
        'database_url': {
            'pattern': r'(?i)(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^/]+',
            'confidence': 0.9,
            'description': 'Database Connection URL'
        },
        
        # 信用卡号 (简化检测)
        'credit_card': {
            'pattern': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b',
            'confidence': 0.7,
            'description': 'Credit Card Number'
        },
    }
    
    def __init__(self, custom_patterns: Optional[Dict[str, str]] = None):
        """
        初始化检测器
        
        Args:
            custom_patterns: 自定义正则模式，格式为 {type: pattern}
        """
        self._compiled_patterns: Dict[str, Pattern] = {}
        self._pattern_confidence: Dict[str, float] = {}
        self._pattern_description: Dict[str, str] = {}
        self._pattern_group: Dict[str, Optional[int]] = {}
        
        # 编译内置模式
        for pattern_name, pattern_info in self.PATTERNS.items():
            try:
                self._compiled_patterns[pattern_name] = re.compile(pattern_info['pattern'])
                self._pattern_confidence[pattern_name] = pattern_info.get('confidence', 0.5)
                self._pattern_description[pattern_name] = pattern_info.get('description', pattern_name)
                self._pattern_group[pattern_name] = pattern_info.get('group')
            except re.error as e:
                logger.warning(f"Failed to compile pattern {pattern_name}: {e}")
        
        # 编译自定义模式
        if custom_patterns:
            for pattern_name, pattern in custom_patterns.items():
                try:
                    self._compiled_patterns[pattern_name] = re.compile(pattern)
                    self._pattern_confidence[pattern_name] = 0.8
                    self._pattern_description[pattern_name] = f"Custom: {pattern_name}"
                    self._pattern_group[pattern_name] = None
                except re.error as e:
                    logger.warning(f"Failed to compile custom pattern {pattern_name}: {e}")
    
    def detect(self, text: str, min_confidence: float = 0.5) -> List[MatchResult]:
        """
        检测文本中的敏感信息
        
        Args:
            text: 待检测文本
            min_confidence: 最低置信度阈值
            
        Returns:
            匹配结果列表
        """
        matches: List[MatchResult] = []
        
        for pattern_name, compiled_pattern in self._compiled_patterns.items():
            confidence = self._pattern_confidence.get(pattern_name, 0.5)
            
            if confidence < min_confidence:
                continue
            
            for match in compiled_pattern.finditer(text):
                group = self._pattern_group.get(pattern_name)
                if group:
                    matched_text = match.group(group)
                    start_pos = match.start(group)
                    end_pos = match.end(group)
                else:
                    matched_text = match.group(0)
                    start_pos = match.start(0)
                    end_pos = match.end(0)
                
                # 过滤过短的匹配
                if len(matched_text) < 8:
                    continue
                
                # 信用卡号额外验证Luhn算法
                if pattern_name == 'credit_card':
                    if not self._validate_luhn(matched_text):
                        continue
                    confidence = 0.95
                
                result = MatchResult(
                    match_type=pattern_name,
                    matched_text=matched_text,
                    start_pos=start_pos,
                    end_pos=end_pos,
                    confidence=confidence,
                    metadata={
                        'description': self._pattern_description.get(pattern_name, ''),
                        'pattern': pattern_name
                    }
                )
                matches.append(result)
        
        # 按位置排序，去重（优先保留置信度高的）
        matches = self._deduplicate_matches(matches)
        
        return matches
    
    def _deduplicate_matches(self, matches: List[MatchResult]) -> List[MatchResult]:
        """去重，重叠区域保留置信度高的匹配"""
        if not matches:
            return []
        
        # 按起始位置排序
        matches = sorted(matches, key=lambda m: (m.start_pos, -m.confidence))
        
        filtered: List[MatchResult] = []
        for match in matches:
            # 检查是否与已保留的匹配重叠
            overlap = False
            for kept in filtered:
                # 检查是否有重叠
                if not (match.end_pos <= kept.start_pos or match.start_pos >= kept.end_pos):
                    overlap = True
                    break
            
            if not overlap:
                filtered.append(match)
        
        return filtered
    
    def _validate_luhn(self, card_number: str) -> bool:
        """使用Luhn算法验证信用卡号"""
        digits = [int(d) for d in card_number if d.isdigit()]
        if len(digits) < 13:
            return False
        
        odd_sum = sum(digits[-1::-2])
        even_sum = sum([sum(divmod(2 * d, 10)) for d in digits[-2::-2]])
        return (odd_sum + even_sum) % 10 == 0
    
    def scan_file(self, file_path: str, min_confidence: float = 0.5) -> List[MatchResult]:
        """扫描文件中的敏感信息"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            return self.detect(content, min_confidence)
        except Exception as e:
            logger.error(f"Failed to scan file {file_path}: {e}")
            return []
    
    def get_supported_types(self) -> List[str]:
        """获取支持的检测类型列表"""
        return list(self._compiled_patterns.keys())
    
    def add_pattern(self, name: str, pattern: str, confidence: float = 0.8) -> bool:
        """添加自定义检测模式"""
        try:
            self._compiled_patterns[name] = re.compile(pattern)
            self._pattern_confidence[name] = confidence
            self._pattern_description[name] = f"Custom: {name}"
            return True
        except re.error as e:
            logger.error(f"Invalid pattern {name}: {e}")
            return False


# 单例实例
default_detector = SensitiveInfoDetector()


def detect_sensitive_info(text: str, min_confidence: float = 0.5) -> List[MatchResult]:
    """便捷函数：使用默认检测器检测敏感信息"""
    return default_detector.detect(text, min_confidence)
