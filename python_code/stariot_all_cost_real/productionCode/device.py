import base64
import pickle
from twisted.internet import protocol
from twisted.internet import reactor
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from DataDemo import *


# 加载DHparameters
def load_parameters():
    with open('parameters.pkl', 'rb') as f:
        p, g = pickle.load(f)
    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters(default_backend())
    return parameters


parameters = load_parameters()
print(f"dh parameters: {parameters}")


def composeDeviceData():
    pass


def analyze_rec_data(data):
    '''解析data，用于区分数据类型一进行下一步判断'''
    # tls_data = pickle.loads(data)
    # secret_data = tlsDecodeData(tls_data)
    # code =secret_data[code]
    # plain_data = decodeSecretDtata(secret_data)
    # plain_data = b'hello'
    print("device analyze message")
    try:
        data = base64.b64decode(data)
        data = pickle.loads(data)
        # code= data['code']
        # message=data['message']
        # code=device_data_dict3['code']
        # message=device_data_dict3['message']
        return data
    except base64.binascii.Error as e:
        return {'code': 302, 'message': data}


class Device(protocol.Protocol):

    def __init__(self):
        self.private_key = parameters.generate_private_key()
        self.switch = {
            201: self.dhExchange,
            202: self.dhKeyAccepted,
            302: self.normalCommunication
        }
        self.shared_key=None
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
        self.transport.write(base64.b64encode(pickle.dumps(dhMessage)))

    def dataReceived(self, data: bytes):
        code = analyze_rec_data(data)['code']
        data = analyze_rec_data(data)['message']
        print(f"code:{code} message from Server (dataRecevied): {data}")
        print(f"shared_key : {self.shared_key}")
        sent_data = self.switch[code](data)
        if sent_data:
            self.transport.write(base64.b64encode(pickle.dumps(sent_data)))
        return

    def dhExchange(self, data):
        server_public_key=data
        server_public_key=serialization.load_pem_public_key(server_public_key)
        self.shared_key = self.private_key.exchange(server_public_key)
        return {'code': 202, 'message': 'device已产生shared_key'}

    #code=202
    def dhKeyAccepted(self,data):
        print(f"device已经产生shared_key: {self.shared_key}")
        return {'code':302,'message': '模拟正常通信'}

    #处理302 的通信信息
    def normalCommunication(self, data):
        data = b'hello server ---Client'
        print(f"客户端进行正常通信: {data}")
        return analyze_rec_data(data)


class DeviceFactory(protocol.ClientFactory):

    def buildProtocol(self, addr):
        return Device()


reactor.connectTCP("localhost", 8003, DeviceFactory())
print("Client is running and connected to localhost:8003")
reactor.run()
