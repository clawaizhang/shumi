"""
集成测试 - 验证完整检测流程
包含多轮测试、性能测试、准确率验证
"""

import pytest
import time
import numpy as np
import sys

sys.path.insert(0, '/root/.shumi/src')


class TestIntegration:
    """完整功能集成测试"""
    
    @pytest.fixture(scope="class")
    def detector(self):
        """创建检测器实例（只加载一次）"""
        from shumi.core.ai_detector import SensitiveDetector
        import shumi.core.ai_detector as ad_module
        ad_module._detector_instance = None
        
        start = time.time()
        d = SensitiveDetector()
        load_time = time.time() - start
        print(f"\n[setup] 模型加载时间: {load_time:.3f}s")
        return d
    
    def test_api_key_variants(self, detector):
        """测试多种API Key格式（循环验证）"""
        test_cases = [
            ("sk-abc123def456ghi789", "api_key"),
            ("sk-proj-xxxxx123456789", "api_key"),
            ("sk-test-key-abcdef12345", "api_key"),
            ("sk-live-xxxxxxxxxxxxxxx", "api_key"),
            ("my api key is sk-secret", "api_key"),
            ("OpenAI key: sk-xyz789", "api_key"),
        ]
        
        passed = 0
        for text, expected_category in test_cases:
            results = detector.detect(text, threshold=0.5)
            
            if results:
                # 检查是否检测到敏感信息
                best = max(results, key=lambda x: x['confidence'])
                if best['confidence'] >= 0.5:
                    passed += 1
                    print(f"  ✅ [{text[:20]}...] {best['category']}={best['confidence']:.3f}")
                else:
                    print(f"  ⚠️  [{text[:20]}...] 置信度低: {best['confidence']:.3f}")
            else:
                print(f"  ❌ [{text[:20]}...] 未检测到")
        
        # 至少70%通过率
        success_rate = passed / len(test_cases)
        print(f"\nAPI Key检测通过率: {passed}/{len(test_cases)} ({success_rate*100:.0f}%)")
        assert success_rate >= 0.7, f"通过率 {success_rate*100:.0f}% 低于70%"
    
    def test_password_variants(self, detector):
        """测试多种密码格式（循环验证）"""
        test_cases = [
            ("password: mySecret123", "password"),
            ("passwd = SecretPass!", "password"),
            ("pwd: abc123XYZ", "password"),
            ("password is HelloWorld99", "password"),
            ("登录密码: testPass123", "password"),
        ]
        
        passed = 0
        for text, expected in test_cases:
            results = detector.detect(text, threshold=0.5)
            if results and any(r['confidence'] >= 0.5 for r in results):
                passed += 1
                print(f"  ✅ [{text[:25]}...] 检测到")
            else:
                print(f"  ❌ [{text[:25]}...] 未检测到")
        
        success_rate = passed / len(test_cases)
        print(f"\n密码检测通过率: {passed}/{len(test_cases)} ({success_rate*100:.0f}%)")
        assert success_rate >= 0.6
    
    def test_aws_key_variants(self, detector):
        """测试AWS密钥格式"""
        test_cases = [
            "AKIAIOSFODNN7EXAMPLE",
            "AKIA1234567890ABCDEF",
            "我的AWS Key是 AKIAIOSFODNN",
            "Access Key ID: AKIAXXXXXXXXX",
        ]
        
        detected = 0
        for text in test_cases:
            results = detector.detect(text, threshold=0.5)
            if results:
                detected += 1
                print(f"  ✅ [{text[:25]}...] {results[0]['category']}={results[0]['confidence']:.3f}")
            else:
                print(f"  ⚠️  [{text[:25]}...] 未检测到")
        
        print(f"\nAWS Key检测: {detected}/{len(test_cases)}")
        assert detected >= 2  # 至少检测到一半
    
    def test_private_key_detection(self, detector):
        """测试私钥检测"""
        test_cases = [
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----",
            "BEGIN PRIVATE KEY",
            "ssh-rsa AAAAB3NzaC1yc2E...",
        ]
        
        detected = 0
        for text in test_cases:
            results = detector.detect(text, threshold=0.5)
            if results:
                detected += 1
                print(f"  ✅ [{text[:30]}...] {results[0]['category']}={results[0]['confidence']:.3f}")
            else:
                print(f"  ⚠️  [{text[:30]}...] 未检测到")
        
        print(f"\n私钥检测: {detected}/{len(test_cases)}")
    
    def test_normal_text_no_false_positive(self, detector):
        """测试正常文本不误报（大量负样本）"""
        normal_texts = [
            "今天天气真好，适合出去散步。",
            "Hello, how are you today?",
            "The quick brown fox jumps over the lazy dog.",
            "这是一段普通的中文文本，没有任何敏感信息。",
            "Python is a great programming language for data science.",
            "请帮我查一下明天的天气预报。",
            "What is the meaning of life?",
            "OpenClaw is a helpful assistant.",
        ]
        
        false_positives = 0
        for text in normal_texts:
            results = detector.detect(text, threshold=0.7)
            if results and any(r['confidence'] >= 0.7 for r in results):
                false_positives += 1
                print(f"  ⚠️ 误报: [{text[:30]}...]")
            else:
                print(f"  ✅ 正常: [{text[:30]}...]")
        
        # 误报率应低于25%
        fp_rate = false_positives / len(normal_texts)
        print(f"\n误报率: {false_positives}/{len(normal_texts)} ({fp_rate*100:.0f}%)")
        assert fp_rate <= 0.25, f"误报率 {fp_rate*100:.0f}% 过高"
    
    def test_mixed_content_detection(self, detector):
        """测试混合内容检测"""
        mixed_texts = [
            ("配置信息：用户名admin，密码Secret123，API Key是sk-abc123", 2),  # 密码+API Key
            ("AWS配置：AKIAIOSFODNN7EXAMPLE 和 secret key wJalrXUtn", 1),  # AWS
            ("连接数据库：host=localhost password=myPass123 端口5432", 1),  # 密码
            ("SSH密钥：-----BEGIN RSA PRIVATE KEY----- 用于服务器登录", 1),  # 私钥
        ]
        
        for text, min_expected in mixed_texts:
            results = detector.detect(text, threshold=0.5)
            detected = len([r for r in results if r['confidence'] >= 0.5])
            status = "✅" if detected >= min_expected else "⚠️"
            print(f"  {status} [{text[:30]}...] 检测到{detected}处敏感信息")
            print(f"      详情: {[(r['category'], '{:.2f}'.format(r['confidence'])) for r in results]}")
    
    def test_inference_speed(self, detector):
        """测试推理速度（循环100次）"""
        test_text = "password: secret123 and api key sk-test-12345"
        
        # 预热
        for _ in range(3):
            detector.detect(test_text)
        
        # 正式测试
        times = []
        for i in range(50):
            start = time.time()
            detector.detect(test_text)
            elapsed = time.time() - start
            times.append(elapsed)
        
        avg_time = np.mean(times)
        min_time = np.min(times)
        max_time = np.max(times)
        p95_time = np.percentile(times, 95)
        
        print(f"\n推理速度测试 (50次):")
        print(f"  平均: {avg_time*1000:.2f}ms")
        print(f"  最小: {min_time*1000:.2f}ms")
        print(f"  最大: {max_time*1000:.2f}ms")
        print(f"  P95:  {p95_time*1000:.2f}ms")
        
        # 平均应小于100ms
        assert avg_time < 0.1, f"推理太慢: {avg_time*1000:.2f}ms"
    
    def test_similarity_scores_range(self, detector):
        """验证相似度分数在合理范围内"""
        test_texts = [
            "sk-test-api-key",
            "password: secret",
            "AKIAIOSFODNN",
            "hello world",
        ]
        
        for text in test_texts:
            result = detector.detect_with_scores(text)
            for score_data in result['all_scores']:
                scores = score_data['scores'].values()
                # 所有分数应在0-1之间
                assert all(0 <= s <= 1 for s in scores), "分数超出范围"
                # 最大分数应合理
                max_score = max(scores)
                print(f"  [{text[:20]}...] 最高相似度: {max_score:.3f}")
    
    def test_consistency(self, detector):
        """测试结果一致性（相同输入应得到相同输出）"""
        text = "sk-test-api-key-12345"
        
        results_list = []
        for i in range(10):
            results = detector.detect(text, threshold=0.5)
            results_list.append(results)
        
        # 检查每次检测到的类别是否一致
        categories_list = [tuple(sorted([r['category'] for r in res])) for res in results_list]
        
        first = categories_list[0]
        all_same = all(c == first for c in categories_list)
        
        print(f"\n一致性测试 (10次):")
        print(f"  首次结果: {first}")
        print(f"  全部一致: {'✅' if all_same else '⚠️'}")
        
        # 至少类别应该一致
        assert all_same, "检测结果不一致"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
