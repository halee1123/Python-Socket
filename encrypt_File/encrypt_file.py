# -*- coding:utf8 -*-

# 导入 cryptography 模块中的序列化和非对称加密相关模块
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# 生成RSA密钥对
private_key = rsa.generate_private_key(
    public_exponent=65537,  # 公钥指数，通常为65537
    key_size=2048,  # 密钥长度，常用2048位
)

# 将私钥保存到文件
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,  # 编码格式为PEM
    format=serialization.PrivateFormat.TraditionalOpenSSL,  # 私钥格式为传统的OpenSSL格式
    encryption_algorithm=serialization.NoEncryption(),  # 不加密私钥
)
with open("Server_key.pem", "wb") as private_key_file:
    private_key_file.write(private_pem)

# 获取公钥
public_key = private_key.public_key()
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,  # 编码格式为PEM
    format=serialization.PublicFormat.SubjectPublicKeyInfo,  # 公钥格式为SubjectPublicKeyInfo
)
with open("Client_key.pem", "wb") as public_key_file:
    public_key_file.write(public_pem)
