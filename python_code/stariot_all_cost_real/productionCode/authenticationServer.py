import base64
import pickle
from twisted.internet import protocol
from twisted.internet import reactor
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from DataDemo import *


def load_parameters():
    with open('parameters.pkl', 'rb') as f:
        p, g = pickle.load(f)
    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters(default_backend())
    return parameters


parameters = load_parameters()
print(f"dh parameters: {parameters}")


# 用于解析来自TCP的报文，将数据传输给具体的业务处理逻辑
def analyze_rec_data(data):
    '''解析data，用于区分数据类型一进行下一步判断'''
    # tls_data = pickle.loads(data)
    # secret_data = tlsDecodeData(tls_data)
    # code =secret_data[code]
    # plain_data = decodeSecretDtata(secret_data)
    # plain_data = b'hello'
    print("Server analyze message")
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
        self.shared_key= None

    def connectionMade(self):
        # compose_device_data = composeDeviceData()
        # self.transport.write(base64.b64encode(pickle.dumps(device_data_dict3)))
        # 将公钥序列化并发送给客户端
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
        code = analyze_rec_data(data)['code']
        data = analyze_rec_data(data)['message']
        print(f"message from Device (dataRecevied): {data}")
        print(f"shared_key : {self.shared_key}")
        #由具体的201 202 301 302代码处理，返回新的 code message类型的信息
        sent_data = self.switch[code](data)
        if sent_data:
            self.transport.write(base64.b64encode(pickle.dumps(sent_data)))
        return

    def dhExchange(self, data):
        client_public_key = data
        client_public_key = serialization.load_pem_public_key(client_public_key)
        self.shared_key = self.private_key.exchange(client_public_key)
        return {'code': 202, 'message': 'Server已产生shared_key'}

    # code=202
    def dhKeyAccepted(self, data):
        print(f"Server已经产生shared_key: {self.shared_key}")
        return {'code': 302, 'message': '模拟正常通信'}

    def issueDeviceSecret(self, data):
        analyze_rec_data(data)

    #处理302通信信息
    def normalCommunication(self, data):
        print(f"正在执行normalCommunication")
        data = b'hello client from Server'
        print(f"服务器进行正常通信: {data}")
        return analyze_rec_data(data)


class AuthenticationServerFactory(protocol.Factory):
    def buildProtocol(self, addr):
        return AuthenticationServer()


reactor.listenTCP(8003, AuthenticationServerFactory())
print("Authen Server is running on port 8003")
reactor.run()
