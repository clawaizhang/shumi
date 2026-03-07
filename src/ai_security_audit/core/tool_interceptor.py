"""
工具调用拦截器 - 拦截大模型工具调用
支持: write_file, edit_file, copy_file, move_file等
"""

import re
import json
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import logging

from ai_security_audit.core.detector import SensitiveInfoDetector, MatchResult
from ai_security_audit.core.encryptor import LocalEncryptor
from ai_security_audit.core.placeholder import PlaceholderManager
from ai_security_audit.core.auditor import SecurityAuditor

logger = logging.getLogger(__name__)


class ToolType(Enum):
    """工具类型"""
    WRITE_FILE = "write_file"
    EDIT_FILE = "edit_file"  
    REPLACE = "replace"
    COPY_FILE = "copy_file"
    MOVE_FILE = "move_file"
    EXEC = "exec"
    BROWSER = "browser"
    MESSAGE = "message"


@dataclass
class ToolCall:
    """工具调用"""
    tool_type: ToolType
    parameters: Dict[str, Any]
    raw_call: str  # 原始调用字符串


class ToolCallInterceptor:
    """
    工具调用拦截器
    
    拦截范围：
    1. write_file - 文件写入内容
    2. edit_file/replace - 文件编辑内容
    3. copy_file/move_file - 文件路径
    4. exec - 命令执行
    5. browser - 浏览器操作URL
    6. message - 消息发送内容
    """
    
    # 工具调用正则模式
    TOOL_PATTERNS = {
        ToolType.WRITE_FILE: re.compile(
            r'write\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']?([^"\']*)["\']?\s*\)',
            re.IGNORECASE
        ),
        ToolType.EDIT_FILE: re.compile(
            r'(?:edit|replace)\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']?([^"\']*)["\']?\s*,\s*["\']?([^"\']*)["\']?\s*\)',
            re.IGNORECASE
        ),
        ToolType.COPY_FILE: re.compile(
            r'copy\s*\(\s*["\']([^"\']+)["\']\s*,\s*["\']([^"\']+)["\']\s*\)',
            re.IGNORECASE
        ),
        ToolType.EXEC: re.compile(
            r'(?:exec|execute|run)\s*\(\s*["\']([^"\']+)["\']\s*\)',
            re.IGNORECASE
        ),
        ToolType.BROWSER: re.compile(
            r'browser\s*\(\s*["\']([^"\']+)["\']\s*\)',
            re.IGNORECASE
        ),
    }
    
    def __init__(
        self,
        detector: SensitiveInfoDetector,
        encryptor: LocalEncryptor,
        placeholder_manager: PlaceholderManager,
        auditor: SecurityAuditor
    ):
        self._detector = detector
        self._encryptor = encryptor
        self._placeholder_manager = placeholder_manager
        self._auditor = auditor
        
        # 敏感参数名
        self._sensitive_params = [
            'password', 'secret', 'token', 'key', 'api_key',
            'private_key', 'credential', 'auth'
        ]
    
    def intercept_tool_calls(self, text: str) -> str:
        """
        拦截并处理工具调用
        
        Args:
            text: 包含工具调用的文本
            
        Returns:
            处理后的文本（敏感信息已脱敏）
        """
        processed = text
        
        # 处理每个工具类型
        for tool_type, pattern in self.TOOL_PATTERNS.items():
            processed = self._process_tool_calls(
                processed, tool_type, pattern
            )
        
        # 处理JSON格式的工具调用
        processed = self._process_json_tool_calls(processed)
        
        return processed
    
    def _process_tool_calls(
        self,
        text: str,
        tool_type: ToolType,
        pattern: re.Pattern
    ) -> str:
        """处理特定工具调用"""
        matches = list(pattern.finditer(text))
        
        # 从后往前处理，避免位置偏移
        for match in reversed(matches):
            try:
                processed_call = self._sanitize_tool_call(
                    tool_type, match.groups(), match.group(0)
                )
                if processed_call != match.group(0):
                    text = text[:match.start()] + processed_call + text[match.end():]
            except Exception as e:
                logger.error(f"Failed to process {tool_type} call: {e}")
        
        return text
    
    def _process_json_tool_calls(self, text: str) -> str:
        """处理JSON格式的工具调用"""
        # 查找JSON对象
        json_pattern = re.compile(r'\{[^{}]*"(?:tool|function|name)"[^{}]*\}')
        
        for match in json_pattern.finditer(text):
            try:
                json_str = match.group(0)
                data = json.loads(json_str)
                
                # 检查是否为工具调用
                if self._is_tool_call_json(data):
                    sanitized = self._sanitize_json_tool_call(data)
                    if sanitized != json_str:
                        text = text[:match.start()] + sanitized + text[match.end():]
            except json.JSONDecodeError:
                continue
            except Exception as e:
                logger.error(f"Failed to process JSON tool call: {e}")
        
        return text
    
    def _is_tool_call_json(self, data: Dict) -> bool:
        """检查JSON是否为工具调用"""
        tool_indicators = ['tool', 'function', 'name', 'action', 'command']
        return any(indicator in data for indicator in tool_indicators)
    
    def _sanitize_tool_call(
        self,
        tool_type: ToolType,
        params: tuple,
        raw_call: str
    ) -> str:
        """对工具调用进行脱敏处理"""
        if tool_type == ToolType.WRITE_FILE:
            file_path, content = params[0], params[1] if len(params) > 1 else ""
            sanitized_content = self._sanitize_content(content)
            if sanitized_content != content:
                return f'write("{file_path}", "{sanitized_content}")'
        
        elif tool_type == ToolType.EDIT_FILE:
            file_path, old_text, new_text = params[0], params[1], params[2]
            sanitized_old = self._sanitize_content(old_text)
            sanitized_new = self._sanitize_content(new_text)
            if sanitized_old != old_text or sanitized_new != new_text:
                return f'edit("{file_path}", "{sanitized_old}", "{sanitized_new}")'
        
        elif tool_type == ToolType.EXEC:
            command = params[0]
            sanitized_cmd = self._sanitize_command(command)
            if sanitized_cmd != command:
                return f'exec("{sanitized_cmd}")'
        
        return raw_call
    
    def _sanitize_json_tool_call(self, data: Dict) -> str:
        """对JSON工具调用进行脱敏"""
        # 深拷贝
        sanitized = json.loads(json.dumps(data))
        
        # 处理参数
        if 'parameters' in sanitized:
            sanitized['parameters'] = self._sanitize_dict_values(
                sanitized['parameters']
            )
        
        if 'args' in sanitized:
            sanitized['args'] = self._sanitize_list_values(sanitized['args'])
        
        # 递归处理嵌套
        sanitized = self._sanitize_nested(sanitized)
        
        return json.dumps(sanitized)
    
    def _sanitize_content(self, content: str) -> str:
        """脱敏内容中的敏感信息"""
        if not content:
            return content
        
        matches = self._detector.detect(content)
        
        processed = content
        for match in sorted(matches, key=lambda m: m.start_pos, reverse=True):
            try:
                encrypted = self._encryptor.encrypt(match.matched_text)
                placeholder = self._placeholder_manager.create_placeholder(
                    encrypted, match.match_type
                )
                processed = (
                    processed[:match.start_pos] +
                    placeholder +
                    processed[match.end_pos:]
                )
                
                # 记录审计
                self._auditor.log_detection(match, placeholder, "tool_interceptor")
            except Exception as e:
                logger.error(f"Failed to encrypt match: {e}")
        
        return processed
    
    def _sanitize_command(self, command: str) -> str:
        """脱敏命令中的敏感信息"""
        # 检测命令中的敏感参数
        matches = self._detector.detect(command)
        
        processed = command
        for match in sorted(matches, key=lambda m: m.start_pos, reverse=True):
            try:
                encrypted = self._encryptor.encrypt(match.matched_text)
                placeholder = self._placeholder_manager.create_placeholder(
                    encrypted, match.match_type
                )
                processed = (
                    processed[:match.start_pos] +
                    placeholder +
                    processed[match.end_pos:]
                )
            except Exception as e:
                logger.error(f"Failed to encrypt command: {e}")
        
        return processed
    
    def _sanitize_dict_values(self, data: Dict) -> Dict:
        """脱敏字典值"""
        result = {}
        for key, value in data.items():
            # 检查键名是否敏感
            if any(sensitive in key.lower() for sensitive in self._sensitive_params):
                if isinstance(value, str):
                    encrypted = self._encryptor.encrypt(value)
                    placeholder = self._placeholder_manager.create_placeholder(
                        encrypted, "sensitive_param"
                    )
                    result[key] = placeholder
                else:
                    result[key] = value
            elif isinstance(value, str):
                result[key] = self._sanitize_content(value)
            else:
                result[key] = value
        return result
    
    def _sanitize_list_values(self, items: List) -> List:
        """脱敏列表值"""
        return [
            self._sanitize_content(item) if isinstance(item, str) else item
            for item in items
        ]
    
    def _sanitize_nested(self, obj: Any) -> Any:
        """递归脱敏嵌套结构"""
        if isinstance(obj, dict):
            return {k: self._sanitize_nested(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._sanitize_nested(item) for item in obj]
        elif isinstance(obj, str):
            return self._sanitize_content(obj)
        return obj
    
    def check_tool_safety(self, tool_call: str) -> Dict[str, Any]:
        """
        检查工具调用安全性
        
        Returns:
            {'safe': bool, 'issues': [...], 'risk_level': 'low/medium/high'}
        """
        issues = []
        risk_level = 'low'
        
        # 检查敏感操作
        dangerous_patterns = [
            (r'rm\s+-rf', '高风险: 递归删除命令'),
            (r'>\s*/dev/', '中风险: 写入系统设备'),
            (r'curl.*\|.*sh', '高风险: 管道执行远程脚本'),
            (r'wget.*-O-\s*\|', '高风险: 管道执行远程内容'),
            (r'eval\s*\(', '高风险: eval执行'),
            (r'exec\s*\(', '高风险: exec执行'),
        ]
        
        for pattern, warning in dangerous_patterns:
            if re.search(pattern, tool_call, re.IGNORECASE):
                issues.append(warning)
                risk_level = 'high'
        
        # 检查敏感信息泄露
        matches = self._detector.detect(tool_call)
        if matches:
            issues.append(f"发现{len(matches)}处敏感信息")
            if any(m.confidence > 0.9 for m in matches):
                risk_level = max(risk_level, 'high')
            elif any(m.confidence > 0.7 for m in matches):
                risk_level = max(risk_level, 'medium')
        
        return {
            'safe': len(issues) == 0,
            'issues': issues,
            'risk_level': risk_level,
            'sensitive_matches': len(matches) if matches else 0
        }
