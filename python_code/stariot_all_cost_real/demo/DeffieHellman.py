import os
import time
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def diffie_hellman_key_exchange():
    # 生成参数
    parameters = dh.generate_parameters(generator=2, key_size=1024)

    # 生成客户端和服务端的私钥
    client_private_key = parameters.generate_private_key()
    server_private_key = parameters.generate_private_key()

    # 直接使用公钥对象进行密钥交换
    client_shared_key = client_private_key.exchange(server_private_key.public_key())
    server_shared_key = server_private_key.exchange(client_private_key.public_key())

    # 验证共享密钥是否相同
    return client_shared_key == server_shared_key

# 测试 Diffie-Hellman 密钥交换所需的时间
start_time = time.time()
diffie_hellman_key_exchange()
end_time = time.time()

print(f"Time taken for Diffie-Hellman key exchange: {end_time - start_time} seconds")