"""
本地加密模块 - 兵部负责
使用RSA-4096 + AES-256-GCM加密敏感信息
"""

import os
import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Optional, Union
from pathlib import Path
import logging

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

logger = logging.getLogger(__name__)


@dataclass
class EncryptedBlob:
    """加密数据容器"""
    encrypted_key: bytes      # RSA加密的AES密钥
    ciphertext: bytes         # AES加密的数据
    nonce: bytes              # AES-GCM nonce
    tag: bytes                # AES-GCM authentication tag
    algorithm: str            # 算法标识
    key_fingerprint: str      # 公钥指纹（用于识别使用的密钥）
    
    def to_dict(self) -> dict:
        """转换为可序列化的字典"""
        return {
            'encrypted_key': base64.b64encode(self.encrypted_key).decode('ascii'),
            'ciphertext': base64.b64encode(self.ciphertext).decode('ascii'),
            'nonce': base64.b64encode(self.nonce).decode('ascii'),
            'tag': base64.b64encode(self.tag).decode('ascii'),
            'algorithm': self.algorithm,
            'key_fingerprint': self.key_fingerprint,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'EncryptedBlob':
        """从字典创建实例"""
        return cls(
            encrypted_key=base64.b64decode(data['encrypted_key']),
            ciphertext=base64.b64decode(data['ciphertext']),
            nonce=base64.b64decode(data['nonce']),
            tag=base64.b64decode(data['tag']),
            algorithm=data['algorithm'],
            key_fingerprint=data['key_fingerprint'],
        )
    
    def to_compact_string(self) -> str:
        """转换为紧凑的字符串格式（用于存储）"""
        data = self.to_dict()
        # 使用URL-safe base64编码所有字段
        combined = f"{data['encrypted_key']}:{data['ciphertext']}:{data['nonce']}:{data['tag']}:{data['key_fingerprint']}"
        return combined
    
    @classmethod
    def from_compact_string(cls, compact: str) -> 'EncryptedBlob':
        """从紧凑字符串解析"""
        parts = compact.split(':')
        if len(parts) != 5:
            raise ValueError("Invalid compact format")
        
        return cls(
            encrypted_key=base64.b64decode(parts[0]),
            ciphertext=base64.b64decode(parts[1]),
            nonce=base64.b64decode(parts[2]),
            tag=base64.b64decode(parts[3]),
            algorithm='RSA-4096+AES-256-GCM',
            key_fingerprint=parts[4],
        )


class LocalEncryptor:
    """
    本地加密处理器 - 使用SSH公钥加密
    
    加密流程：
    1. 生成随机AES-256-GCM密钥
    2. 使用AES-GCM加密敏感内容
    3. 使用RSA公钥加密AES密钥
    4. 存储：{encrypted_key, ciphertext, nonce, tag}
    
    解密流程：
    1. 使用RSA私钥解密AES密钥
    2. 使用AES-GCM解密密文
    3. 验证认证标签
    """
    
    AES_KEY_SIZE = 32  # 256 bits
    AES_NONCE_SIZE = 12  # 96 bits for GCM
    RSA_KEY_SIZE = 4096
    
    def __init__(self, ssh_public_key_path: Optional[Union[str, Path]] = None):
        """
        初始化加密器
        
        Args:
            ssh_public_key_path: SSH公钥文件路径（OpenSSH格式）
        """
        self._public_key = None
        self._key_fingerprint = None
        
        if ssh_public_key_path:
            self.load_public_key(ssh_public_key_path)
    
    def load_public_key(self, key_path: Union[str, Path]) -> None:
        """
        加载SSH公钥
        
        Args:
            key_path: SSH公钥文件路径
        """
        key_path = Path(key_path).expanduser().resolve()
        
        if not key_path.exists():
            raise FileNotFoundError(f"Public key not found: {key_path}")
        
        key_content = key_path.read_text().strip()
        
        # 支持OpenSSH格式和PEM格式
        if key_content.startswith('ssh-rsa') or key_content.startswith('ssh-ed25519'):
            # OpenSSH格式
            key_bytes = serialization.load_ssh_public_key(
                key_content.encode(),
                backend=default_backend()
            )
        elif 'BEGIN PUBLIC KEY' in key_content or 'BEGIN RSA PUBLIC KEY' in key_content:
            # PEM格式
            key_bytes = serialization.load_pem_public_key(
                key_content.encode(),
                backend=default_backend()
            )
        else:
            raise ValueError("Unsupported public key format")
        
        self._public_key = key_bytes
        
        # 计算密钥指纹
        key_bytes_for_fingerprint = self._public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self._key_fingerprint = hashlib.sha256(key_bytes_for_fingerprint).hexdigest()[:16]
        
        logger.info(f"Loaded public key with fingerprint: {self._key_fingerprint}")
    
    def generate_key_pair(self, private_key_path: Union[str, Path], 
                          public_key_path: Union[str, Path]) -> None:
        """
        生成新的RSA密钥对
        
        Args:
            private_key_path: 私钥保存路径
            public_key_path: 公钥保存路径
        """
        private_key_path = Path(private_key_path).expanduser()
        public_key_path = Path(public_key_path).expanduser()
        
        # 生成私钥
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.RSA_KEY_SIZE,
            backend=default_backend()
        )
        
        # 保存私钥（加密）
        private_key_path.parent.mkdir(parents=True, exist_ok=True)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(
                secrets.token_bytes(32)  # 随机密码，实际需要用户输入
            )
        )
        private_key_path.write_bytes(private_pem)
        private_key_path.chmod(0o600)  # 确保权限正确
        
        # 保存公钥
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_key_path.parent.mkdir(parents=True, exist_ok=True)
        public_key_path.write_bytes(public_pem)
        public_key_path.chmod(0o644)
        
        logger.info(f"Generated key pair: {private_key_path}, {public_key_path}")
    
    def encrypt(self, plaintext: str) -> EncryptedBlob:
        """
        加密敏感信息
        
        Args:
            plaintext: 待加密的明文
            
        Returns:
            EncryptedBlob: 加密后的数据
            
        Raises:
            RuntimeError: 如果未加载公钥
        """
        if self._public_key is None:
            raise RuntimeError("Public key not loaded. Call load_public_key() first.")
        
        # 生成随机AES密钥
        aes_key = secrets.token_bytes(self.AES_KEY_SIZE)
        
        # 生成随机nonce
        nonce = secrets.token_bytes(self.AES_NONCE_SIZE)
        
        # AES-GCM加密
        aesgcm = AESGCM(aes_key)
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, None)
        
        # 分离密文和认证标签
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]
        
        # RSA加密AES密钥
        encrypted_key = self._public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return EncryptedBlob(
            encrypted_key=encrypted_key,
            ciphertext=ciphertext,
            nonce=nonce,
            tag=tag,
            algorithm='RSA-4096+AES-256-GCM',
            key_fingerprint=self._key_fingerprint or 'unknown'
        )
    
    def encrypt_bytes(self, data: bytes) -> EncryptedBlob:
        """加密字节数据"""
        if self._public_key is None:
            raise RuntimeError("Public key not loaded.")
        
        aes_key = secrets.token_bytes(self.AES_KEY_SIZE)
        nonce = secrets.token_bytes(self.AES_NONCE_SIZE)
        
        aesgcm = AESGCM(aes_key)
        ciphertext_with_tag = aesgcm.encrypt(nonce, data, None)
        
        ciphertext = ciphertext_with_tag[:-16]
        tag = ciphertext_with_tag[-16:]
        
        encrypted_key = self._public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return EncryptedBlob(
            encrypted_key=encrypted_key,
            ciphertext=ciphertext,
            nonce=nonce,
            tag=tag,
            algorithm='RSA-4096+AES-256-GCM',
            key_fingerprint=self._key_fingerprint or 'unknown'
        )
    
    def get_key_fingerprint(self) -> Optional[str]:
        """获取当前加载公钥的指纹"""
        return self._key_fingerprint
    
    def is_ready(self) -> bool:
        """检查加密器是否已准备好（已加载公钥）"""
        return self._public_key is not None


class LocalDecryptor:
    """
    本地解密处理器 - 需要RSA私钥
    
    警告：私钥必须严格保密，只能在安全环境中使用
    """
    
    def __init__(self, private_key_path: Optional[Union[str, Path]] = None,
                 password: Optional[bytes] = None):
        """
        初始化解密器
        
        Args:
            private_key_path: RSA私钥文件路径
            password: 私钥密码（如果私钥已加密）
        """
        self._private_key = None
        
        if private_key_path:
            self.load_private_key(private_key_path, password)
    
    def load_private_key(self, key_path: Union[str, Path], 
                         password: Optional[bytes] = None) -> None:
        """
        加载RSA私钥
        
        Args:
            key_path: 私钥文件路径
            password: 私钥密码
        """
        key_path = Path(key_path).expanduser().resolve()
        
        if not key_path.exists():
            raise FileNotFoundError(f"Private key not found: {key_path}")
        
        key_content = key_path.read_bytes()
        
        # 尝试PEM格式
        try:
            self._private_key = serialization.load_pem_private_key(
                key_content,
                password=password,
                backend=default_backend()
            )
            logger.info("Loaded private key (PEM format)")
            return
        except Exception:
            pass
        
        # 尝试DER格式
        try:
            self._private_key = serialization.load_der_private_key(
                key_content,
                password=password,
                backend=default_backend()
            )
            logger.info("Loaded private key (DER format)")
            return
        except Exception:
            pass
        
        raise ValueError("Unsupported private key format")
    
    def decrypt(self, blob: EncryptedBlob) -> str:
        """
        解密数据
        
        Args:
            blob: 加密数据容器
            
        Returns:
            解密后的明文
            
        Raises:
            RuntimeError: 如果未加载私钥
            ValueError: 如果解密失败
        """
        if self._private_key is None:
            raise RuntimeError("Private key not loaded.")
        
        try:
            # RSA解密AES密钥
            aes_key = self._private_key.decrypt(
                blob.encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # AES-GCM解密
            aesgcm = AESGCM(aes_key)
            ciphertext_with_tag = blob.ciphertext + blob.tag
            plaintext = aesgcm.decrypt(blob.nonce, ciphertext_with_tag, None)
            
            return plaintext.decode('utf-8')
            
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
    
    def decrypt_bytes(self, blob: EncryptedBlob) -> bytes:
        """解密为字节数据"""
        if self._private_key is None:
            raise RuntimeError("Private key not loaded.")
        
        aes_key = self._private_key.decrypt(
            blob.encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        aesgcm = AESGCM(aes_key)
        ciphertext_with_tag = blob.ciphertext + blob.tag
        return aesgcm.decrypt(blob.nonce, ciphertext_with_tag, None)


def generate_key_pair(private_path: str, public_path: str) -> None:
    """便捷函数：生成RSA密钥对"""
    encryptor = LocalEncryptor()
    encryptor.generate_key_pair(private_path, public_path)
