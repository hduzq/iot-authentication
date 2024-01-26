import pickle
import os
import time

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from twisted.internet import protocol
from twisted.internet import reactor
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from DataDemo import *

SELECTED_SECRET_AREA = b'1'
PRODUCT_SECRET = b'product_secret_1'
DEVICE_SECRET_AREA1 = None
DEVICE_SECRET_AREA2 = None


# 加载DHparameters
def load_parameters():
    with open('parameters.pkl', 'rb') as f:
        p, g = pickle.load(f)
    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters(default_backend())
    return parameters


parameters = load_parameters()
print(f"dh parameters: {parameters}")

encryption_key = None


def composeDeviceData():
    pass


class Device(protocol.Protocol):

    def __init__(self):
        self.private_key = parameters.generate_private_key()
        self.switch = {
            201: self.dhExchange,
            202: self.dhKeyAccepted,
            301: self.requestDeviceSecret301,
            302: self.normalCommunication,
            303: self.acceptDeviceSecret303
        }
        self.shared_key = None
        self.dh_encrypt_key = None
        self.ds_encrypt_key = None

    def connectionMade(self):
        # compose_device_data = composeDeviceData()
        # self.transport.write(base64.b64encode(pickle.dumps(device_data_dict3)))
        # 将公钥序列化并发送给服务器
        public_key_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        dhMessage = {
            'code': 201,
            'message': public_key_bytes
        }
        # self.transport.write(base64.b64encode(public_key_bytes) + b'\n')
        self.transport.write(pickle.dumps(dhMessage))

    def dataReceived(self, data: bytes):
        # Start timer
        start_time = time.time_ns()

        # 用于评估通信开销
        bytes_length = len(data)
        print(f"Device Received {bytes_length} bytes")

        dict = self.analyze_rec_data(data)
        code = dict['code']
        data = dict['message']
        if code == 303:
            data = dict['Device_secret']
        # print(f"code:{code} message from Server (dataRecevied): {data}")
        # print(f"shared_key : {self.shared_key}")
        sent_data = self.switch[code](data)
        if sent_data:
            self.transport.write(sent_data)

        # End timer
        end_time = time.time_ns()
        # Calculate execution time in nanoseconds
        execution_time_ns = end_time - start_time
        print(f" 'dataReceived' Execution time: {execution_time_ns} ns")
        return

    def dhExchange(self, data):
        server_public_key = data
        server_public_key = serialization.load_pem_public_key(server_public_key)
        self.shared_key = self.private_key.exchange(server_public_key)
        self.generatedDHEncryptKey()
        result = {'code': 202, 'message': 'device已产生shared_key'}
        result = self.dh_encrypt_message(result)
        # result = base64.b64encode(pickle.dumps(result))
        return result

    # code=202
    def dhKeyAccepted(self, data):
        print(f"device已经产生shared_key: {self.shared_key}")
        result = {'code': 301, 'message': '模拟下发证书'}
        result = self.dh_encrypt_message(result)
        # result = base64.b64encode(pickle.dumps(result))
        return result

    def requestDeviceSecret301(self, data):
        '''需要返回一个直接用于发送的data'''
        self.generateDSEncryptKey(PRODUCT_SECRET)
        requestData = {'code': 301, 'message': '******device id for DS********'}
        dsCipher = self.ds_encrypt_message(requestData)
        dhCipher = self.dh_encrypt_message(dsCipher)
        return dhCipher

    def acceptDeviceSecret303(self, data):
        DEVICE_SECRET_AREA1 = data
        # 根据新的密钥加密数据
        self.generateDSEncryptKey(DEVICE_SECRET_AREA1)
        requestData = {'code': 401, 'message': 'Device开始利用ds进行加密通信'}
        dsCipher = self.ds_encrypt_message(requestData)
        dhCipher = self.dh_encrypt_message(dsCipher)
        return dhCipher

    # 处理302 的通信信息
    def normalCommunication(self, data):
        data = {'code': 302, 'message': 'hello server ---Client'}
        # ds加密
        data = self.dh_encrypt_message(data)
        print(f"客户端进行正常通信: {data}")
        return data

    def generatedDHEncryptKey(self):
        '''根据dh key派生出dh加密密钥'''
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

        return pickle.loads(plaintext)

    def generateDSEncryptKey(self, DeviceSecret):
        '''根据ps ds派生出ds加密密钥'''
        self.ds_encrypt_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(DeviceSecret)
        return self.ds_encrypt_key

    def ds_encrypt_message(self, plain_message):
        '''利用ds_encrypt_key加密'''
        # 生成随机的初始化向量（IV）
        iv = os.urandom(16)

        # 创建加密器
        cipher = Cipher(
            algorithms.AES(self.ds_encrypt_key),
            modes.CFB(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        # 加密消息
        # plain_message=json.dumps(plain_message)
        plain_message = pickle.dumps(plain_message)
        ciphertext = encryptor.update(plain_message) + encryptor.finalize()
        return iv + ciphertext

    def ds_decrypt_message(self, iv_ciphertext):
        '''利用ds_encrypt_key解密'''
        # 分离IV和密文
        iv, ciphertext = iv_ciphertext[:16], iv_ciphertext[16:]

        # 创建解密器
        cipher = Cipher(
            algorithms.AES(self.ds_encrypt_key),
            modes.CFB(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()

        # 解密消息
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return pickle.loads(plaintext)

    def analyze_rec_data(self, data):
        # 将信息处理成{code: 301, message: xxxx}
        print("Client analyze message..................")
        if self.dh_encrypt_key:
            # 有加密情况不需要base编码
            # data = base64.b64decode(data)
            # data = pickle.loads(data)
            data = self.dh_decrypt_message(data)
            if self.ds_encrypt_key:
                data = self.ds_decrypt_message(data)
            return data
        # data = base64.b64decode(data)
        data = pickle.loads(data)
        return data


class DeviceFactory(protocol.ClientFactory):

    def buildProtocol(self, addr):
        return Device()


def start_client():
    reactor.connectTCP("localhost", 8003, DeviceFactory())
    print("Client is running and connected to localhost:8003")
    reactor.run()
