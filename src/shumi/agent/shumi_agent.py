#!/usr/bin/env python3
"""
Shumi Agent - 独立常驻进程
监听 Shumi 检测事件并发送独立通知
"""

import json
import os
import sys
import time
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

# 添加 shumi 到路径
sys.path.insert(0, os.path.expanduser('~/.shumi/src'))


class ShumiAgent:
    """
    Shumi Agent - 常驻进程
    
    监听 ~/.openclaw/security/events/shumi.events.jsonl
    只处理 event_type 以 "shumi." 开头的事件
    """
    
    def __init__(self):
        self.events_dir = Path.home() / ".openclaw" / "security" / "events"
        self.events_file = self.events_dir / "shumi.events.jsonl"
        self.position_file = self.events_dir / ".shumi.agent.position"
        
        # 确保目录存在
        self.events_dir.mkdir(parents=True, exist_ok=True)
        
        # 读取上次读取位置
        self.last_position = self._read_position()
        
        print(f"[Shumi Agent] 启动")
        print(f"[Shumi Agent] 监听文件: {self.events_file}")
        print(f"[Shumi Agent] 起始位置: {self.last_position}")
    
    def _read_position(self) -> int:
        """读取上次读取的文件位置"""
        if self.position_file.exists():
            try:
                return int(self.position_file.read_text().strip())
            except:
                return 0
        return 0
    
    def _save_position(self, position: int):
        """保存当前读取位置"""
        try:
            self.position_file.write_text(str(position))
        except Exception as e:
            print(f"[Shumi Agent] 保存位置失败: {e}")
    
    def _is_shumi_event(self, event: Dict[str, Any]) -> bool:
        """
        检查是否为 Shumi 专属事件
        
        条件：
        1. event_type 以 "shumi." 开头
        2. source 为 "shumi"
        """
        event_type = event.get("event_type", "")
        source = event.get("source", "")
        
        return (
            event_type.startswith("shumi.") and 
            source == "shumi"
        )
    
    def _send_notification(self, event: Dict[str, Any]):
        """发送通知消息"""
        context = event.get("context", {})
        payload = event.get("payload", {})
        event_type = event.get("event_type", "")
        
        chat_id = context.get("chat_id")
        channel = context.get("channel")
        
        if not chat_id or not channel:
            print(f"[Shumi Agent] 跳过: 缺少 chat_id 或 channel")
            return
        
        # 根据事件类型生成消息
        if event_type == "shumi.detection":
            detected_types = payload.get("detected_types", [])
            confidence = payload.get("confidence", 0)
            
            # 类型中文映射
            type_names = {
                'api_key': 'API密钥',
                'password': '密码',
                'token': '令牌',
                'aws_key': 'AWS密钥',
                'private_key': '私钥'
            }
            type_str = '、'.join([type_names.get(t, t) for t in detected_types])
            
            message = f"🔒 枢密：检测到{type_str}，已加密保护"
            
        elif event_type == "shumi.error":
            error_type = payload.get("error_type", "未知错误")
            message = f"⚠️ 枢密：检测出错 ({error_type})"
            
        else:
            # 其他事件类型暂不通知
            return
        
        # 使用 openclaw CLI 发送消息
        try:
            result = subprocess.run(
                [
                    "openclaw", "message", "send",
                    "--channel", channel,
                    "--target", chat_id,
                    "--message", message
                ],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                print(f"[Shumi Agent] ✅ 已发送通知到 {channel}:{chat_id}")
            else:
                print(f"[Shumi Agent] ❌ 发送失败: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            print(f"[Shumi Agent] ❌ 发送超时")
        except Exception as e:
            print(f"[Shumi Agent] ❌ 发送异常: {e}")
    
    def _process_event(self, event: Dict[str, Any]):
        """处理单个事件"""
        # 检查是否已处理
        meta = event.get("meta", {})
        if meta.get("processed"):
            return
        
        # 检查是否为 Shumi 事件
        if not self._is_shumi_event(event):
            print(f"[Shumi Agent] 跳过非Shumi事件: {event.get('event_type')}")
            return
        
        print(f"[Shumi Agent] 处理事件: {event.get('event_id')} ({event.get('event_type')})")
        
        # 发送通知
        self._send_notification(event)
        
        # 标记为已处理（可选：可以修改原文件或记录到 processed 文件）
        # 这里简单记录日志
    
    def _read_new_events(self):
        """读取新事件"""
        if not self.events_file.exists():
            return
        
        try:
            with open(self.events_file, "r", encoding="utf-8") as f:
                # 跳到上次位置
                f.seek(self.last_position)
                
                new_lines = []
                for line in f:
                    line = line.strip()
                    if line:
                        new_lines.append(line)
                
                # 更新位置
                self.last_position = f.tell()
                self._save_position(self.last_position)
                
                return new_lines
                
        except Exception as e:
            print(f"[Shumi Agent] 读取事件文件失败: {e}")
            return []
    
    def run(self):
        """主循环"""
        print(f"[Shumi Agent] 开始监听...")
        print(f"[Shumi Agent] 按 Ctrl+C 停止")
        print()
        
        try:
            while True:
                # 读取新事件
                new_lines = self._read_new_events()
                
                if new_lines:
                    print(f"[Shumi Agent] 发现 {len(new_lines)} 个新事件")
                    
                    for line in new_lines:
                        try:
                            event = json.loads(line)
                            self._process_event(event)
                        except json.JSONDecodeError:
                            print(f"[Shumi Agent] 跳过无效JSON: {line[:50]}")
                        except Exception as e:
                            print(f"[Shumi Agent] 处理事件失败: {e}")
                
                # 等待下一次轮询
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\n[Shumi Agent] 收到停止信号")
            print("[Shumi Agent] 已停止")


def main():
    """入口函数"""
    agent = ShumiAgent()
    agent.run()


if __name__ == "__main__":
    main()
