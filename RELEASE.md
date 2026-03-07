# 发布说明 - ONNX模型

## 预编译ONNX模型

为提升用户体验，我们提供预编译的ONNX模型，用户无需本地转换。

### 模型信息

- **文件**: `model.onnx`
- **大小**: ~650 KB
- **加载时间**: 0.16秒
- **内存占用**: ~96 MB

### 下载地址

```
https://github.com/clawaizhang/shumi/releases/download/v0.3.0-onnx/model.onnx
```

### 手动上传步骤

1. 访问 https://github.com/clawaizhang/shumi/releases
2. 创建新 Release: `v0.3.0-onnx`
3. 上传文件: `model.onnx`
4. 发布 Release

### 安装脚本使用

安装脚本会自动从Release下载模型：

```bash
curl -fsSL https://raw.githubusercontent.com/clawaizhang/shumi/main/install.sh | bash
```
