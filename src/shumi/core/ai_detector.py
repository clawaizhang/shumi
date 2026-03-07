#!/usr/bin/env python3
"""
兵部 - 敏感信息检测器核心集成模块
职责: 实现完整检测流程、Embedding编码、相似度匹配、多尺度检测
"""

import json
import re
import numpy as np
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass

# 延迟导入，避免启动时加载
_model = None
_encoder = None

def get_encoder(model_name: str = 'sentence-transformers/all-MiniLM-L6-v2'):
    """获取Encoder单例"""
    global _encoder
    if _encoder is None:
        try:
            from sentence_transformers import SentenceTransformer
            print(f"[兵部] 加载模型: {model_name}")
            _encoder = SentenceTransformer(model_name)
            print(f"[兵部] 模型加载完成")
        except ImportError:
            raise ImportError("请安装 sentence-transformers: pip install sentence-transformers")
    return _encoder


@dataclass
class DetectionResult:
    """检测结果数据类"""
    text: str
    category: str
    similarity: float
    threshold: float
    severity: str
    position: int = 0
    verified: bool = False


class SensitiveDetector:
    """
    敏感信息检测器
    
    基于Embedding模型的语义相似度检测，支持多尺度分块检测
    """
    
    # 默认阈值配置
    DEFAULT_THRESHOLDS = {
        "api_keys": 0.75,
        "passwords": 0.70,
        "tokens": 0.72,
        "jwt": 0.72,
        "credentials": 0.68,
        "crypto_keys": 0.80
    }
    
    # 严重级别映射
    SEVERITY_MAP = {
        "api_keys": "high",
        "passwords": "high",
        "tokens": "medium",
        "jwt": "medium",
        "credentials": "high",
        "crypto_keys": "critical"
    }
    
    # 正则验证模式（二次验证用）
    REGEX_PATTERNS = {
        "api_keys": [
            r'AKIA[0-9A-Z]{16}',
            r'ghp_[a-zA-Z0-9]{36}',
            r'glpat-[a-zA-Z0-9\-]{20}',
            r'sk-[a-zA-Z0-9]{48}',
            r'sk_live_[a-zA-Z0-9]{24}',
            r'xoxb-[0-9]{12}-[a-zA-Z0-9]{12}-[a-zA-Z0-9]{24}'
        ],
        "tokens": [
            r'Bearer\s+[a-zA-Z0-9_\-\.]+',
            r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'
        ],
        "crypto_keys": [
            r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
            r'-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----'
        ]
    }
    
    def __init__(
        self,
        model_name: str = 'sentence-transformers/all-MiniLM-L6-v2',
        chunk_strategy_file: Optional[str] = None,
        thresholds: Optional[Dict[str, float]] = None
    ):
        """
        初始化检测器
        
        Args:
            model_name: Embedding模型名称
            chunk_strategy_file: 分块策略配置文件路径
            thresholds: 自定义阈值配置
        """
        self.model_name = model_name
        self.encoder = None  # 延迟加载
        self.dimension = 384  # all-MiniLM-L6-v2的输出维度
        
        # 加载分块策略
        self.chunk_strategy = self._load_chunk_strategy(chunk_strategy_file)
        
        # 设置阈值
        self.thresholds = thresholds or self.DEFAULT_THRESHOLDS
        
        # 加载类别中心向量（简化版本，使用随机向量作为示例）
        self.category_embeddings = self._init_category_embeddings()
        
    def _load_chunk_strategy(self, strategy_file: Optional[str]) -> Dict:
        """加载分块策略"""
        if strategy_file and Path(strategy_file).exists():
            with open(strategy_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        
        # 默认分块策略
        return {
            "api_keys": [
                {"name": "short", "chunk_size": 30, "step_size": 15},
                {"name": "medium", "chunk_size": 50, "step_size": 25}
            ],
            "passwords": [
                {"name": "short", "chunk_size": 20, "step_size": 10},
                {"name": "medium", "chunk_size": 35, "step_size": 17}
            ],
            "tokens": [
                {"name": "medium", "chunk_size": 60, "step_size": 30},
                {"name": "long", "chunk_size": 120, "step_size": 60}
            ],
            "jwt": [
                {"name": "short", "chunk_size": 200, "step_size": 100},
                {"name": "medium", "chunk_size": 450, "step_size": 225},
                {"name": "long", "chunk_size": 900, "step_size": 450}
            ],
            "credentials": [
                {"name": "medium", "chunk_size": 100, "step_size": 50}
            ],
            "crypto_keys": [
                {"name": "short", "chunk_size": 500, "step_size": 250},
                {"name": "long", "chunk_size": 2000, "step_size": 1000}
            ]
        }
    
    def _init_category_embeddings(self) -> Dict[str, np.ndarray]:
        """
        初始化类别中心向量
        
        在实际部署中，这些应该是从样本库计算得到的真实向量
        这里使用随机向量作为占位符
        """
        np.random.seed(42)
        embeddings = {}
        for category in self.DEFAULT_THRESHOLDS.keys():
            # 生成随机单位向量
            vec = np.random.randn(self.dimension)
            vec = vec / np.linalg.norm(vec)
            embeddings[category] = vec
        return embeddings
    
    def _get_encoder(self):
        """获取Encoder（延迟加载）"""
        if self.encoder is None:
            self.encoder = get_encoder(self.model_name)
        return self.encoder
    
    def detect(self, text: str) -> Dict:
        """
        检测文本中的敏感信息
        
        Args:
            text: 待检测文本
            
        Returns:
            检测结果字典
        """
        import time
        start_time = time.time()
        
        results = {
            'input_length': len(text),
            'candidates_found': 0,
            'detections': [],
            'processing_time_ms': 0
        }
        
        # 1. 预处理 - 提取候选片段
        candidates = self._extract_candidates(text)
        results['candidates_found'] = len(candidates)
        
        if not candidates:
            results['processing_time_ms'] = (time.time() - start_time) * 1000
            return results
        
        # 2. 生成Embedding
        embeddings = self._encode_candidates(candidates)
        
        # 3. 相似度匹配
        detections = self._match_similarity(candidates, embeddings)
        
        # 4. 规则二次验证
        verified_detections = self._verify_with_regex(detections)
        
        results['detections'] = [
            {
                'text': d.text[:100] + '...' if len(d.text) > 100 else d.text,
                'position': d.position,
                'category': d.category,
                'similarity': round(d.similarity, 4),
                'threshold': d.threshold,
                'severity': d.severity,
                'verified': d.verified
            }
            for d in verified_detections
        ]
        
        results['processing_time_ms'] = round((time.time() - start_time) * 1000, 2)
        
        return results
    
    def _extract_candidates(self, text: str) -> List[Tuple[str, int]]:
        """
        提取候选片段
        
        返回: [(片段文本, 起始位置), ...]
        """
        candidates = []
        
        # 多尺度分块检测
        # 首先尝试预测可能的类别
        likely_categories = self._predict_likely_categories(text)
        
        # 收集所有相关分块策略
        all_configs = []
        for category in likely_categories:
            if category in self.chunk_strategy:
                all_configs.extend(self.chunk_strategy[category])
        
        # 去重（相同分块大小只保留一个）
        seen_sizes = set()
        unique_configs = []
        for cfg in sorted(all_configs, key=lambda x: x['chunk_size']):
            if cfg['chunk_size'] not in seen_sizes:
                seen_sizes.add(cfg['chunk_size'])
                unique_configs.append(cfg)
        
        # 应用分块策略
        for config in unique_configs:
            chunks = self._sliding_window(
                text, 
                config['chunk_size'], 
                config['step_size']
            )
            candidates.extend(chunks)
        
        # 去重
        seen = set()
        unique_candidates = []
        for chunk, pos in candidates:
            if chunk not in seen:
                seen.add(chunk)
                unique_candidates.append((chunk, pos))
        
        return unique_candidates
    
    def _predict_likely_categories(self, text: str) -> List[str]:
        """预测文本可能包含的敏感信息类别"""
        text_lower = text.lower()
        scores = {}
        
        # 基于关键词匹配预测
        keywords = {
            "api_keys": ["api", "key", "secret", "token", "ak", "sk"],
            "passwords": ["password", "pwd", "pass", "passwd"],
            "tokens": ["token", "bearer", "auth", "session"],
            "jwt": ["jwt", "eyj", "bearer eyj"],
            "credentials": ["mysql", "postgres", "mongodb", "redis", "connection", "database"],
            "crypto_keys": ["private key", "rsa", "ssh", "pem", "key----"]
        }
        
        for category, words in keywords.items():
            score = sum(1 for word in words if word in text_lower)
            if score > 0:
                scores[category] = score
        
        # 返回得分最高的类别，如果没有匹配则返回所有类别
        if scores:
            return sorted(scores.keys(), key=lambda x: scores[x], reverse=True)[:3]
        return list(self.DEFAULT_THRESHOLDS.keys())
    
    def _sliding_window(self, text: str, chunk_size: int, step_size: int) -> List[Tuple[str, int]]:
        """滑动窗口分块"""
        chunks = []
        for i in range(0, len(text) - chunk_size + 1, step_size):
            chunk = text[i:i + chunk_size]
            chunks.append((chunk, i))
        
        # 处理剩余部分
        if len(text) > chunk_size and len(text) % step_size != 0:
            chunks.append((text[-chunk_size:], len(text) - chunk_size))
        elif len(text) <= chunk_size:
            chunks.append((text, 0))
        
        return chunks
    
    def _encode_candidates(self, candidates: List[Tuple[str, int]]) -> np.ndarray:
        """编码候选片段"""
        texts = [c[0] for c in candidates]
        encoder = self._get_encoder()
        
        # 批量编码
        embeddings = encoder.encode(
            texts,
            normalize_embeddings=True,
            batch_size=32,
            show_progress_bar=False
        )
        return embeddings
    
    def _match_similarity(self, candidates: List[Tuple[str, int]], embeddings: np.ndarray) -> List[DetectionResult]:
        """相似度匹配"""
        detections = []
        
        for i, ((text, pos), emb) in enumerate(zip(candidates, embeddings)):
            # 计算与各类别的相似度
            for category, cat_emb in self.category_embeddings.items():
                similarity = self._cosine_similarity(emb, cat_emb)
                threshold = self.thresholds.get(category, 0.7)
                
                if similarity >= threshold:
                    detections.append(DetectionResult(
                        text=text,
                        category=category,
                        similarity=similarity,
                        threshold=threshold,
                        severity=self.SEVERITY_MAP.get(category, "medium"),
                        position=pos
                    ))
        
        # 按相似度降序排序
        detections.sort(key=lambda x: x.similarity, reverse=True)
        return detections
    
    def _cosine_similarity(self, a: np.ndarray, b: np.ndarray) -> float:
        """计算余弦相似度"""
        return float(np.dot(a, b))
    
    def _verify_with_regex(self, detections: List[DetectionResult]) -> List[DetectionResult]:
        """使用正则表达式进行二次验证"""
        verified = []
        
        for det in detections:
            patterns = self.REGEX_PATTERNS.get(det.category, [])
            if patterns:
                det.verified = any(re.search(p, det.text, re.IGNORECASE) for p in patterns)
            else:
                det.verified = True  # 没有正则模式的类别直接通过
            
            verified.append(det)
        
        return verified
    
    def batch_detect(self, texts: List[str]) -> List[Dict]:
        """批量检测"""
        return [self.detect(text) for text in texts]


# 测试函数
def test_detector():
    """测试检测器"""
    print("=" * 60)
    print("兵部 - 敏感信息检测器测试")
    print("=" * 60)
    
    # 初始化检测器
    detector = SensitiveDetector()
    
    # 测试样本
    test_cases = [
        # API Key
        'api_key = "AKIAIOSFODNN7EXAMPLE"',
        # Password
        'password = "mysecretpassword123"',
        # JWT
        'token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"',
        # Database credential
        'DATABASE_URL = "mysql://admin:secret123@localhost:3306/mydb"',
        # Mixed content
        """
        Config:
        api_key = "sk-abcdefghijklmnopqrstuvwxyz123456"
        password = "SuperSecretPassword!2024"
        db_connection = "postgres://user:pass@db.example.com:5432/production"
        """
    ]
    
    for i, test_text in enumerate(test_cases, 1):
        print(f"\n测试 {i}:")
        print(f"  输入: {test_text[:80]}...")
        
        result = detector.detect(test_text)
        
        print(f"  处理时间: {result['processing_time_ms']}ms")
        print(f"  候选片段: {result['candidates_found']}")
        print(f"  检测结果: {len(result['detections'])} 个")
        
        for det in result['detections'][:3]:  # 只显示前3个
            print(f"    - {det['category']}: 相似度 {det['similarity']:.3f} "
                  f"(阈值 {det['threshold']}, 级别 {det['severity']})")
    
    print("\n" + "=" * 60)
    print("测试完成!")
    print("=" * 60)


if __name__ == "__main__":
    test_detector()
