import base64
import json
import os
import pickle
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from twisted.internet import protocol
from twisted.internet import reactor
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from DataDemo import *


def load_parameters():
    '''load Deffie-Hellman key parameters'''
    with open('parameters.pkl', 'rb') as f:
        p, g = pickle.load(f)
    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters(default_backend())
    return parameters


parameters = load_parameters()
print(f"dh parameters: {parameters}")


def tlsDecodeData(tls_data):
    pass


def decodeSecretDtata(secret_data):
    pass


class AuthenticationServer(protocol.Protocol):
    def __init__(self):
        self.private_key = parameters.generate_private_key()
        self.switch = {
            201: self.dhExchange,
            202: self.dhKeyAccepted,
            301: self.issueDeviceSecret,
            302: self.normalCommunication
        }
        self.shared_key = None
        self.dh_encrypt_key = None

    def connectionMade(self):
        #建立连接交换公钥
        public_key_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        dhMessage = {
            'code': 201,
            'message': public_key_bytes
        }
        self.transport.write(base64.b64encode(pickle.dumps(dhMessage)))

    def dataReceived(self, data):
        code = self.analyze_rec_data(data)['code']
        data = self.analyze_rec_data(data)['message']
        print(f"message from Device (dataRecevied): {data}")
        print(f"shared_key : {self.shared_key}")
        # 由具体的201 202 301 302代码处理，返回base64类型的数据
        sent_data = self.switch[code](data)
        if sent_data:
            self.transport.write(sent_data)
        return

    def dhExchange(self, data):
        '''accepted code=201'''
        client_public_key = data
        client_public_key = serialization.load_pem_public_key(client_public_key)
        self.shared_key = self.private_key.exchange(client_public_key)
        # 为了产生dhEncryptKey
        self.generatedDHEncryptKey()
        result = {'code': 202, 'message': 'Server已产生shared_key'}
        result = self.dh_encrypt_message(result)
        result = base64.b64encode(pickle.dumps(result))
        return result

    def dhKeyAccepted(self, data):
        '''accepted code=202'''
        print(f"Server已经产生shared_key: {self.shared_key}")
        result = {'code': 302, 'message': '模拟正常通信'}
        result = self.dh_encrypt_message(result)
        result = base64.b64encode(pickle.dumps(result))
        return result

    def issueDeviceSecret(self, data):
        pass

    def normalCommunication(self, data):
        '''accepted code=302'''
        print(f"Server is sending normalCommunication .......")
        data = {'code': 302, 'message': 'hello client from Server'}
        data = self.dh_encrypt_message(data)
        data = base64.b64encode(pickle.dumps(data))
        print(f"服务器进行正常通信: {data}")
        return data

    def generatedDHEncryptKey(self):
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(self.shared_key)
        self.dh_encrypt_key = derived_key

    def dh_encrypt_message(self, plain_message):
        # 生成随机的初始化向量（IV）
        iv = os.urandom(16)

        # 创建加密器
        cipher = Cipher(
            algorithms.AES(self.dh_encrypt_key),
            modes.CFB(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        # 加密消息
        # plain_message=json.dumps(plain_message)
        plain_message = pickle.dumps(plain_message)
        ciphertext = encryptor.update(plain_message) + encryptor.finalize()
        return iv + ciphertext

    def dh_decrypt_message(self, iv_ciphertext):
        '''
        返回 python dict
        sample: {'code' :202 ,'message':'.......'}
        必须使用序列化后的数据进行解密
        最后将plaintext进行反序列化
        '''

        # 分离IV和密文
        iv, ciphertext = iv_ciphertext[:16], iv_ciphertext[16:]

        # 创建解密器
        cipher = Cipher(
            algorithms.AES(self.dh_encrypt_key),
            modes.CFB(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()

        # 解密消息
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = pickle.loads(plaintext)
        return plaintext

    def analyze_rec_data(self, data):
        print("Server analyze message..................")
        if self.dh_encrypt_key:
            # 前两行用于
            data = base64.b64decode(data)
            data = pickle.loads(data)
            data = self.dh_decrypt_message(data)
            return data
        data = base64.b64decode(data)
        data = pickle.loads(data)
        return data


class AuthenticationServerFactory(protocol.Factory):
    def buildProtocol(self, addr):
        return AuthenticationServer()


reactor.listenTCP(8003, AuthenticationServerFactory())
print("Authen Server is running on port 8003")
reactor.run()
