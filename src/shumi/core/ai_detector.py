"""
ONNX敏感信息检测器 - 完全替代PyTorch
快速加载，高效推理，真正的相似度检测
"""

import os
import json
import numpy as np
from typing import List, Dict, Any, Optional
from pathlib import Path
import logging

logger = logging.getLogger('shumi')

# 单例实例缓存
_detector_instance = None


class SensitiveDetector:
    """
    基于ONNX的敏感信息检测器 (单例模式)
    
    特点:
    - 0.16秒快速加载
    - 纯ONNX推理，无PyTorch依赖
    - 单例模式确保只加载一次模型
    - 真正的相似度检测（与预训练类别中心比较）
    """
    
    def __new__(cls, model_path: Optional[str] = None):
        """单例模式：确保只有一个实例"""
        global _detector_instance
        if _detector_instance is None:
            _detector_instance = super().__new__(cls)
            _detector_instance._initialized = False
        return _detector_instance
    
    def __init__(self, model_path: Optional[str] = None):
        """
        初始化检测器 (单例模式，只初始化一次)
        
        Args:
            model_path: ONNX模型路径，默认使用预编译模型
        """
        # 防止重复初始化
        if self._initialized:
            return
        
        # 默认路径
        self.models_dir = Path(os.path.expanduser("~/.shumi/models"))
        if model_path:
            self.model_path = Path(model_path).expanduser()
        else:
            self.model_path = self.models_dir / "model.onnx"
        self.centers_path = self.models_dir / "sensitive_centers.json"
        
        self._session = None
        self._tokenizer = None
        self._centers = {}  # 类别中心向量
        self._categories = []  # 类别名称列表
        
        self._load_model()
        self._load_centers()
        self._initialized = True
    
    def _load_model(self):
        """加载ONNX模型和本地tokenizer"""
        import onnxruntime as ort
        from transformers import AutoTokenizer
        
        if not self.model_path.exists():
            raise FileNotFoundError(f"ONNX模型不存在: {self.model_path}")
        
        logger.info("[枢密] 加载ONNX模型...")
        
        # 加载ONNX运行时
        self._session = ort.InferenceSession(
            str(self.model_path),
            providers=['CPUExecutionProvider']
        )
        
        # 从本地加载tokenizer（无需网络）
        self._tokenizer = AutoTokenizer.from_pretrained(str(self.models_dir))
        
        logger.info("[枢密] ✅ ONNX模型加载完成！")
    
    def _load_centers(self):
        """加载敏感类别中心向量"""
        if not self.centers_path.exists():
            raise FileNotFoundError(f"类别中心文件不存在: {self.centers_path}")
        
        with open(self.centers_path, 'r') as f:
            centers_data = json.load(f)
        
        self._categories = list(centers_data.keys())
        self._centers = {
            cat: np.array(vec, dtype=np.float32) 
            for cat, vec in centers_data.items()
        }
        
        logger.info(f"[枢密] 加载了 {len(self._categories)} 个敏感类别: {self._categories}")
    
    def encode(self, texts: List[str]) -> np.ndarray:
        """
        编码文本为向量（batch=1，模型限制）
        
        Args:
            texts: 文本列表
            
        Returns:
            向量数组 (N, 384)
        """
        embeddings = []
        for text in texts:
            emb = self._encode_single(text)
            embeddings.append(emb)
        return np.array(embeddings, dtype=np.float32)
    
    def _encode_single(self, text: str) -> np.ndarray:
        """编码单条文本（batch=1）"""
        # Tokenize
        inputs = self._tokenizer(
            [text],
            padding=True,
            truncation=True,
            max_length=256,
            return_tensors="np"
        )
        
        # ONNX推理
        ort_inputs = {
            'input_ids': inputs['input_ids'],
            'attention_mask': inputs['attention_mask']
        }
        ort_outputs = self._session.run(None, ort_inputs)
        
        # Mean pooling
        token_embeddings = ort_outputs[0][0]  # [seq_len, 384]
        attention_mask = inputs['attention_mask'][0]
        
        mask_expanded = np.expand_dims(attention_mask, -1).astype(np.float32)
        sum_emb = np.sum(token_embeddings * mask_expanded, axis=0)
        sum_mask = np.clip(mask_expanded.sum(axis=0), a_min=1e-9, a_max=None)
        embedding = sum_emb / sum_mask
        
        # L2归一化
        embedding = embedding / np.linalg.norm(embedding)
        
        return embedding
    
    def detect(self, text: str, threshold: float = 0.55) -> List[Dict[str, Any]]:
        """
        检测文本中的敏感信息（真正的相似度检测）
        
        Args:
            text: 输入文本
            threshold: 相似度阈值（默认0.55）
            
        Returns:
            检测结果列表
        """
        # 分块处理
        chunks = self._create_chunks(text)
        
        if not chunks:
            return []
        
        results = []
        
        # 对每个chunk进行相似度检测
        for chunk in chunks:
            chunk_text = chunk['text']
            
            # 编码chunk
            embedding = self._encode_single(chunk_text)
            
            # 计算与各类别的相似度
            best_category = None
            best_similarity = 0
            
            for category, center_vec in self._centers.items():
                similarity = np.dot(embedding, center_vec)  # 余弦相似度（已归一化）
                if similarity > best_similarity:
                    best_similarity = similarity
                    best_category = category
            
            # 如果最大相似度超过阈值，判定为敏感信息
            if best_similarity >= threshold:
                results.append({
                    'text': chunk_text,
                    'category': best_category,
                    'start': chunk['start'],
                    'end': chunk['end'],
                    'confidence': float(best_similarity)
                })
        
        return results
    
    def detect_with_scores(self, text: str) -> Dict[str, Any]:
        """
        检测并返回所有类别的相似度分数（用于调试）
        
        Args:
            text: 输入文本
            
        Returns:
            {'chunks': [...], 'scores': {category: score}}
        """
        chunks = self._create_chunks(text)
        
        all_scores = []
        for chunk in chunks:
            embedding = self._encode_single(chunk['text'])
            
            scores = {}
            for category, center_vec in self._centers.items():
                scores[category] = float(np.dot(embedding, center_vec))
            
            all_scores.append({
                'text': chunk['text'],
                'scores': scores
            })
        
        return {'chunks': chunks, 'all_scores': all_scores}
    
    def _create_chunks(self, text: str, window_size: int = 50, step_size: int = 25) -> List[Dict]:
        """创建滑动窗口分块"""
        chunks = []
        for i in range(0, len(text), step_size):
            chunk_text = text[i:i + window_size]
            if len(chunk_text) >= 10:  # 至少10个字符
                chunks.append({
                    'text': chunk_text,
                    'start': i,
                    'end': min(i + window_size, len(text))
                })
        return chunks
    
    @property
    def categories(self):
        """返回敏感类别列表"""
        return self._categories
