from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import socket
import base64
import pickle

# 创建 socket 并连接到服务器
c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
c.connect(("localhost", 12345))

# 接收服务器的公钥和参数
server_public_key_pem = c.recv(2048)
params_numbers = pickle.loads(c.recv(4096))
parameters = params_numbers.parameters(default_backend())

# 使用接收到的参数生成私钥
private_key = parameters.generate_private_key()

pem = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

server_public_key = serialization.load_pem_public_key(
    server_public_key_pem,
    backend=default_backend()
)

# 发送公钥
c.send(pem)

# 计算共享密钥
shared_key = private_key.exchange(server_public_key)

# 使用 HKDF 来派生密钥
derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"handshake data",
    backend=default_backend()
).derive(shared_key)

print('Derived key:', base64.b64encode(derived_key))