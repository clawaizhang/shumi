"""
ONNX模型单元测试 - 验证真正的相似度检测
"""

import pytest
import numpy as np
import os
import sys

# 确保使用项目代码
sys.path.insert(0, '/root/.shumi/src')


class TestONNXModel:
    """ONNX模型基础功能测试"""
    
    def test_model_file_exists(self):
        """测试模型文件存在"""
        model_path = os.path.expanduser("~/.shumi/models/model.onnx")
        assert os.path.exists(model_path), f"模型文件不存在: {model_path}"
    
    def test_tokenizer_files_exist(self):
        """测试tokenizer文件已预下载"""
        models_dir = os.path.expanduser("~/.shumi/models")
        assert os.path.exists(f"{models_dir}/tokenizer.json"), "tokenizer.json 不存在"
        assert os.path.exists(f"{models_dir}/vocab.txt"), "vocab.txt 不存在"
    
    def test_centers_file_exists(self):
        """测试敏感类别中心文件存在"""
        centers_path = os.path.expanduser("~/.shumi/models/sensitive_centers.json")
        assert os.path.exists(centers_path), f"类别中心文件不存在: {centers_path}"
    
    def test_model_load(self):
        """测试模型能正常加载"""
        import onnxruntime as ort
        
        model_path = os.path.expanduser("~/.shumi/models/model.onnx")
        session = ort.InferenceSession(
            model_path,
            providers=['CPUExecutionProvider']
        )
        
        assert session is not None
        assert len(session.get_inputs()) > 0
        assert len(session.get_outputs()) > 0
    
    def test_model_inference(self):
        """测试模型能执行推理并返回有效输出"""
        import onnxruntime as ort
        from transformers import AutoTokenizer
        
        model_path = os.path.expanduser("~/.shumi/models/model.onnx")
        models_dir = os.path.expanduser("~/.shumi/models")
        
        session = ort.InferenceSession(model_path, providers=['CPUExecutionProvider'])
        tokenizer = AutoTokenizer.from_pretrained(models_dir)  # 本地加载
        
        # 测试输入
        test_text = "sk-test-api-key-12345"
        inputs = tokenizer([test_text], padding=True, truncation=True, 
                          max_length=256, return_tensors="np")
        
        ort_inputs = {
            'input_ids': inputs['input_ids'],
            'attention_mask': inputs['attention_mask']
        }
        ort_outputs = session.run(None, ort_inputs)
        
        # 验证输出
        assert len(ort_outputs) > 0
        assert not np.isnan(ort_outputs[0]).any()
        assert not np.isinf(ort_outputs[0]).any()
    
    def test_mean_pooling(self):
        """测试Mean Pooling能正常计算"""
        import onnxruntime as ort
        from transformers import AutoTokenizer
        
        model_path = os.path.expanduser("~/.shumi/models/model.onnx")
        models_dir = os.path.expanduser("~/.shumi/models")
        
        session = ort.InferenceSession(model_path, providers=['CPUExecutionProvider'])
        tokenizer = AutoTokenizer.from_pretrained(models_dir)
        
        test_text = "password: secret123"
        inputs = tokenizer([test_text], padding=True, truncation=True, 
                          max_length=256, return_tensors="np")
        
        ort_inputs = {
            'input_ids': inputs['input_ids'],
            'attention_mask': inputs['attention_mask']
        }
        ort_outputs = session.run(None, ort_inputs)
        
        # Mean pooling
        token_embeddings = ort_outputs[0][0]
        attention_mask = inputs['attention_mask'][0]
        
        mask_expanded = np.expand_dims(attention_mask, -1).astype(np.float32)
        sum_emb = np.sum(token_embeddings * mask_expanded, axis=0)
        sum_mask = np.clip(mask_expanded.sum(axis=0), a_min=1e-9, a_max=None)
        embedding = sum_emb / sum_mask
        embedding = embedding / np.linalg.norm(embedding)
        
        # 验证
        assert embedding.shape == (384,)
        assert not np.isnan(embedding).any()
        assert not np.isinf(embedding).any()
        assert abs(np.linalg.norm(embedding) - 1.0) < 0.01  # 已归一化


class TestSensitiveDetector:
    """敏感信息检测器测试（真正的相似度检测）"""
    
    @pytest.fixture
    def detector(self):
        """创建检测器实例"""
        from shumi.core.ai_detector import SensitiveDetector
        # 重置单例
        import shumi.core.ai_detector as ad_module
        ad_module._detector_instance = None
        return SensitiveDetector()
    
    def test_detector_loads(self, detector):
        """测试检测器能正常加载"""
        assert detector._session is not None
        assert detector._tokenizer is not None
        assert len(detector.categories) > 0
        assert len(detector._centers) > 0
    
    def test_encode_single(self, detector):
        """测试单条文本编码"""
        embedding = detector._encode_single("test text")
        assert embedding.shape == (384,)
        assert abs(np.linalg.norm(embedding) - 1.0) < 0.01
    
    def test_similarity_detection_api_key(self, detector):
        """测试能检测API Key"""
        text = "我的API Key是 sk-abc123def456ghi789"
        results = detector.detect(text, threshold=0.5)
        
        # 应该检测到敏感信息
        assert len(results) > 0
        
        # 检查是否有 api_key 类别（或相似类别）
        categories = [r['category'] for r in results]
        assert 'api_key' in categories or 'token' in categories
    
    def test_similarity_detection_password(self, detector):
        """测试能检测密码"""
        text = "password: mySecretPassword123"
        results = detector.detect(text, threshold=0.5)
        
        assert len(results) > 0
        categories = [r['category'] for r in results]
        assert 'password' in categories
    
    def test_no_false_positive(self, detector):
        """测试普通文本不误报"""
        text = "这是一段普通的文本，没有敏感信息"
        results = detector.detect(text, threshold=0.7)
        
        # 高阈值下应该没有检测结果
        assert len(results) == 0 or all(r['confidence'] < 0.7 for r in results)
    
    def test_detect_with_scores(self, detector):
        """测试分数输出功能"""
        text = "sk-test-key"
        result = detector.detect_with_scores(text)
        
        assert 'chunks' in result
        assert 'all_scores' in result
        
        # 检查每个类别都有分数
        for score_data in result['all_scores']:
            for category in detector.categories:
                assert category in score_data['scores']
                assert 0 <= score_data['scores'][category] <= 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
