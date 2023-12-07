from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import socket
import base64
import pickle

# 创建 Diffie-Hellman 参数
parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

# 生成私钥
private_key = parameters.generate_private_key()

pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# 创建 socket 并监听连接
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("localhost", 12345))
s.listen(1)

print('Waiting for connection...')
conn, addr = s.accept()
print('Connected by', addr)

# 发送公钥和参数
conn.send(pem)
conn.send(pickle.dumps(parameters.parameter_numbers()))

# 接收客户端的公钥
client_public_key_pem = conn.recv(2048)
client_public_key = serialization.load_pem_public_key(
    client_public_key_pem,
    backend=default_backend()
)

# 计算共享密钥
shared_key = private_key.exchange(client_public_key)

# 使用 HKDF 来派生密钥
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"handshake data",
    backend=default_backend()
).derive(shared_key)

print('Derived key:', base64.b64encode(derived_key))