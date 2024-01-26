import csv
import os
import pickle
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from twisted.internet import protocol
from twisted.internet import reactor
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from DataDemo import *

import psutil

SELECTED_SECRET_AREA = b'1'
PRODUCT_SECRET = b'product_secret_1'
DEVICE_SECRET_AREA1 = b'Device_secret_Area1'


# DEVICE_SECRET_AREA2 = None

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
            301: self.issueDeviceSecret301,
            302: self.normalCommunication,
            401: self.communicationWithDS401
        }
        self.shared_key = None
        self.dh_encrypt_key = None
        self.ds_encrypt_key = None
        # self.initial_memory_used=None

    def connectionMade(self):
        # 建立连接交换公钥
        public_key_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        dhMessage = {
            'code': 201,
            'message': public_key_bytes
        }
        # self.initial_memory_used = psutil.virtual_memory().used
        self.transport.write(pickle.dumps(dhMessage))

    def dataReceived(self, data):
        # Start timer
        start_time = time.time_ns()

        # 用于评估通信开销
        bytes_length = len(data)
        print(f"Received {bytes_length} bytes")

        dict = self.analyze_rec_data(data)
        code = dict['code']
        data = dict['message']
        # print(f"message from Device (dataRecevied): {data}")
        # print(f"shared_key : {self.shared_key}")
        # 由具体的201 202 301 302代码处理，返回base64类型的数据
        sent_data = self.switch[code](data)
        if sent_data:
            self.transport.write(sent_data)

            # End timer
        end_time = time.time_ns()
        # Calculate execution time in nanoseconds
        execution_time_ns = end_time - start_time
        print(f" 'dataReceived' Execution time: {execution_time_ns} ns")
        # print_resource_usage("After dataReceived -----authenticationServer")
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
        # result = base64.b64encode(pickle.dumps(result))
        return result

    def dhKeyAccepted(self, data):
        '''accepted code=202'''
        #print(f"Server已经产生shared_key: {self.shared_key}")
        self.generateDSEncryptKey(PRODUCT_SECRET)
        result = {'code': 301, 'message': '模拟下发证书'}
        result = self.dh_encrypt_message(result)
        # result = base64.b64encode(pickle.dumps(result))
        return result

    def issueDeviceSecret301(self, data):
        responseData = {'code': 303,
                        'message': '******I can decode message********',
                        'Device_secret': DEVICE_SECRET_AREA1}
        dsCipher = self.ds_encrypt_message(responseData)
        dhCipher = self.dh_encrypt_message(dsCipher)
        self.generateDSEncryptKey(DEVICE_SECRET_AREA1)
        return dhCipher

    def normalCommunication(self, data):
        '''accepted code=302'''
        print(f"code: 302 Server is sending normalCommunication .......")
        data = {'code': 302, 'message': 'hello client from Server'}
        # ds加密
        data = self.dh_encrypt_message(data)
        print(f"服务器进行正常通信: {data}")
        return data

    def communicationWithDS401(self, data):
        print('Sever已经收到401消息')
        responseData = {'code': 401,
                        'message': '******communicationWithDS401********',
                        'Device_secret': DEVICE_SECRET_AREA1}
        dsCipher = self.ds_encrypt_message(responseData)
        dhCipher = self.dh_encrypt_message(dsCipher)
        self.generateDSEncryptKey(DEVICE_SECRET_AREA1)
        log_performance_data("communicationWithDS401")
        return dhCipher

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

        # Start timer
        start_time = time.time_ns()

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

        # End timer
        end_time = time.time_ns()
        # Calculate execution time in nanoseconds
        execution_time_ns = end_time - start_time

        print(f" 'ds_encrypt_message' Execution time: {execution_time_ns} ns")

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
        # 返回{code:202 ,message: xxxxx}
        # print("Server analyze message..................")
        # 如果ds密钥存在就利用ds密钥解除密
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


class AuthenticationServerFactory(protocol.Factory):
    def buildProtocol(self, addr):
        return AuthenticationServer()

def print_initial_resource_usage():
    cpu_usage = psutil.cpu_percent()
    memory_usage = psutil.virtual_memory().percent
    print(f"Initial CPU Usage: {cpu_usage}%, Initial Memory Usage: {memory_usage}%")

print_initial_resource_usage()
initial_memory_used=psutil.virtual_memory().used


def print_resource_usage(event):
    cpu_usage = psutil.cpu_percent()
    memory_usage = psutil.virtual_memory().percent
    print(f"{event} - CPU Usage: {cpu_usage}%, Memory Usage: {memory_usage}%")

#步骤1: 收集和存储数据
#每当进行性能监控时，将数据追加到CSV文件中。
def log_performance_data(event):
    file_exists = os.path.isfile('performance_data.csv') and os.path.getsize('performance_data.csv') > 0
    with open('performance_data.csv', 'a', newline='') as csvfile:
        fieldnames = ['timestamp', 'event', 'cpu_usage', 'memory_usage']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        if not file_exists:
            writer.writeheader()
        data = {
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'event': event,
            'cpu_usage': psutil.cpu_percent(),
            'memory_usage': psutil.virtual_memory().used-initial_memory_used
        }
        if data['cpu_usage']>0:
            writer.writerow(data)

reactor.listenTCP(8003, AuthenticationServerFactory())
print("Authen Server is running on port 8003")
reactor.run()
