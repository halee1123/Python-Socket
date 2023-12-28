# Client.py

# 导入 Python 的 socket 模块，用于网络通信
import socket

# 导入 cryptography 模块，用于加密解密操作
from cryptography.hazmat.backends import default_backend

# 导入 cryptography 中的序列化和哈希模块
from cryptography.hazmat.primitives import serialization, hashes

# 导入 cryptography 中的非对称加密相关模块
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# 导入 configparser 模块，用于解析配置文件
import configparser

def load_config():
    # 读取配置文件中的 IP 地址和端口信息
    config = configparser.ConfigParser()  # 创建 ConfigParser 对象，用于解析 INI 配置文件
    config.read('config.ini')  # 读取配置文件
    common_config = config['Common']  # 获取 Common 部分的配置信息
    return common_config['ip'], int(common_config['port'])  # 返回解析得到的 IP 地址和端口号

def encrypt_data(data, public_key):
    # 使用公钥加密数据
    encrypted_data = public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data  # 返回加密后的数据

def send_data(data, public_key):
    # 向服务器发送加密数据
    ip, port = load_config()  # 获取配置文件中的 IP 地址和端口号
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建 TCP 套接字
    client.connect((ip, port))  # 连接到服务器

    # 加密数据
    encrypted_data = encrypt_data(data, public_key)

    # 发送加密数据给服务器
    client.send(encrypted_data)

    print(f'Data sent to server: {data}')

    # 接收并解密命令执行结果
    result = client.recv(4096).decode()
    print(f'Result from server: {result}')

    client.close()  # 关闭连接

if __name__ == "__main__":
    # 从文件中加载公钥
    with open("Client_key.pem", "rb") as public_key_file:
        public_pem = public_key_file.read()
        public_key = serialization.load_pem_public_key(
            public_pem,
            backend=default_backend()
        )

    data_to_send = input("Enter data to send to server: ")
    send_data(data_to_send, public_key)
