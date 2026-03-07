#!/bin/bash
#
# 枢密 (Shumi) 启动脚本
# 启动/停止/重启枢密服务
#

SERVICE_NAME="shumi"
LOG_DIR="${HOME}/.shumi/logs"
PID_FILE="${LOG_DIR}/shumi.pid"

case "$1" in
    start)
        if [ -f "$PID_FILE" ] && kill -0 $(cat "$PID_FILE") 2>/dev/null; then
            echo "枢密服务已在运行 (PID: $(cat $PID_FILE))"
            exit 0
        fi
        
        echo "启动枢密服务..."
        mkdir -p "$LOG_DIR"
        
        # 后台运行检测服务
        nohup python3 -c "
import sys
sys.path.insert(0, '${HOME}/.shumi/src')

import os
os.environ['HF_ENDPOINT'] = 'https://hf-mirror.com'

from shumi.core.ai_detector import SensitiveDetector

# 创建检测器（预加载模型）
detector = SensitiveDetector()

# 保持运行，等待检测请求
import time
print('枢密服务已启动，等待检测请求...')
while True:
    time.sleep(60)  # 每分钟检查一次
" > "${LOG_DIR}/shumi.log" 2>&1 &
        
        echo $! > "$PID_FILE"
        echo "枢密服务已启动 (PID: $(cat $PID_FILE))"
        ;;
        
    stop)
        if [ -f "$PID_FILE" ]; then
            PID=$(cat "$PID_FILE")
            if kill -0 "$PID" 2>/dev/null; then
                echo "停止枢密服务 (PID: $PID)..."
                kill "$PID"
                rm -f "$PID_FILE"
                echo "枢密服务已停止"
            else
                echo "枢密服务未运行"
                rm -f "$PID_FILE"
            fi
        else
            echo "枢密服务未运行"
        fi
        ;;
        
    restart)
        $0 stop
        sleep 2
        $0 start
        ;;
        
    status)
        if [ -f "$PID_FILE" ] && kill -0 $(cat "$PID_FILE") 2>/dev/null; then
            echo "枢密服务运行中 (PID: $(cat $PID_FILE))"
        else
            echo "枢密服务未运行"
        fi
        ;;
        
    *)
        echo "用法: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
