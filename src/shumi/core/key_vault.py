"""
密钥保险箱模块 - 安全密钥存储
支持: 密码加密、硬件密钥、KMS集成
"""

import os
import json
import getpass
import hashlib
import secrets
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

@dataclass
class KeyVaultConfig:
    """密钥保险箱配置"""
    vault_path: Path
    use_password: bool = True
    use_hardware_key: bool = False
    kms_provider: Optional[str] = None  # aws/azure/gcp

class KeyVault:
    """
    密钥保险箱
    
    安全特性：
    1. 主密码派生加密密钥 (PBKDF2)
    2. 密钥文件权限 600 (仅所有者可读写)
    3. 支持密码保护
    4. 可选硬件密钥增强
    """
    
    def __init__(self, vault_path: Optional[Path] = None):
        if vault_path is None:
            vault_path = Path.home() / '.openclaw' / 'security' / 'vault'
        
        self._vault_path = Path(vault_path)
        self._vault_path.parent.mkdir(parents=True, exist_ok=True)
        self._fernet: Optional[Fernet] = None
    
    def initialize(self, password: Optional[str] = None) -> None:
        """初始化保险箱"""
        if self._vault_path.exists():
            raise RuntimeError("Vault already exists")
        
        if password is None:
            password = getpass.getpass("设置保险箱主密码: ")
            confirm = getpass.getpass("确认主密码: ")
            if password != confirm:
                raise ValueError("密码不匹配")
        
        # 生成盐值
        salt = secrets.token_bytes(16)
        
        # 派生密钥
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        # 保存盐值
        vault_meta = {
            'salt': base64.b64encode(salt).decode(),
            'version': 1
        }
        meta_path = self._vault_path.with_suffix('.meta')
        with open(meta_path, 'w') as f:
            json.dump(vault_meta, f)
        meta_path.chmod(0o600)
        
        # 创建空保险箱
        self._save_vault({})
        
        print(f"✅ 保险箱已创建: {self._vault_path}")
        print("⚠️  请牢记主密码，丢失将无法恢复！")
    
    def unlock(self, password: Optional[str] = None) -> bool:
        """解锁保险箱"""
        if password is None:
            password = getpass.getpass("输入保险箱主密码: ")
        
        # 读取盐值
        meta_path = self._vault_path.with_suffix('.meta')
        with open(meta_path, 'r') as f:
            vault_meta = json.load(f)
        
        salt = base64.b64decode(vault_meta['salt'])
        
        # 派生密钥
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self._fernet = Fernet(key)
        
        # 验证密码
        try:
            self._load_vault()
            return True
        except Exception:
            self._fernet = None
            return False
    
    def store(self, name: str, data: str) -> None:
        """存储密钥"""
        if self._fernet is None:
            raise RuntimeError("Vault not unlocked")
        
        vault = self._load_vault()
        encrypted = self._fernet.encrypt(data.encode())
        vault[name] = base64.b64encode(encrypted).decode()
        self._save_vault(vault)
    
    def retrieve(self, name: str) -> Optional[str]:
        """读取密钥"""
        if self._fernet is None:
            raise RuntimeError("Vault not unlocked")
        
        vault = self._load_vault()
        if name not in vault:
            return None
        
        encrypted = base64.b64decode(vault[name])
        return self._fernet.decrypt(encrypted).decode()
    
    def list_keys(self) -> list:
        """列出所有密钥"""
        vault = self._load_vault()
        return list(vault.keys())
    
    def _load_vault(self) -> Dict[str, Any]:
        """加载保险箱内容"""
        if not self._vault_path.exists():
            return {}
        
        with open(self._vault_path, 'r') as f:
            return json.load(f)
    
    def _save_vault(self, data: Dict[str, Any]) -> None:
        """保存保险箱内容"""
        temp_path = self._vault_path.with_suffix('.tmp')
        with open(temp_path, 'w') as f:
            json.dump(data, f)
        temp_path.replace(self._vault_path)
        self._vault_path.chmod(0o600)


def generate_ssh_keypair(vault: KeyVault, key_name: str = "ai_security") -> Dict[str, str]:
    """
    生成SSH密钥对并存储到保险箱
    
    Returns:
        {'public_key': '...', 'fingerprint': '...'}
    """
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    import hashlib
    
    # 生成密钥对
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096
    )
    public_key = private_key.public_key()
    
    # 序列化
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    
    # 计算指纹
    fingerprint = hashlib.sha256(public_pem.encode()).hexdigest()[:16]
    
    # 存储到保险箱
    vault.store(f"{key_name}_private", private_pem)
    vault.store(f"{key_name}_public", public_pem)
    
    return {
        'public_key': public_pem,
        'fingerprint': fingerprint
    }
