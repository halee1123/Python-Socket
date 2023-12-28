# Server.py
import socket
import subprocess
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import configparser



def load_config():
    # 读取配置文件中的 IP 地址和端口信息
    config = configparser.ConfigParser()
    config.read('config.ini')
    common_config = config['Common']
    return common_config['ip'], int(common_config['port'])

def decrypt_data(data, private_key):
    # 使用私钥解密数据
    decrypted_data = private_key.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data.decode()

def execute_command(command):
    # 执行 shell 命令并返回结果
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout

def start_server(private_key):
    # 启动服务器
    ip, port = load_config()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建 TCP 套接字
    server.bind((ip, port))  # 绑定 IP 地址和端口
    server.listen(1)  # 监听连接

    print(f"Server listening on {ip}:{port}")

    while True:
        client, addr = server.accept()  # 接受连接
        print(f"Connection from {addr}")

        data = client.recv(4096)  # 接收数据
        if not data:
            break

        decrypted_data = decrypt_data(data, private_key)
        print(f"Decrypted data received from client: {decrypted_data}")

        # 执行 shell 命令
        command_result = execute_command(decrypted_data)
        print(f"Command result: {command_result}")

        # 发送命令执行结果给客户端
        client.send(command_result.encode())

        client.close()  # 关闭连接

if __name__ == "__main__":
    # 从文件中加载私钥
    with open("Server_key.pem", "rb") as private_key_file:
        private_pem = private_key_file.read()
        private_key = serialization.load_pem_private_key(
            private_pem,
            password=None,
            backend=default_backend()
        )

    start_server(private_key)
