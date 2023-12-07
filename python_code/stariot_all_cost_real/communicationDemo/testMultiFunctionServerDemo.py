import base64
import pickle
from base64 import *
from twisted.internet import protocol
from twisted.internet import reactor

from python_code.stariot_all_cost_real.communicationDemo.DataDemo import *

#用于
def analyze_rec_data(data):
    '''解析data，用于区分数据类型一进行下一步判断'''
    # tls_data = pickle.loads(data)
    # secret_data = tlsDecodeData(tls_data)
    # code =secret_data[code]
    # plain_data = decodeSecretDtata(secret_data)
    # plain_data = b'hello'
    print("Server产生的消息")
    try:
        data = base64.b64decode(data)
        data = pickle.loads(data)
        # code= data['code']
        # message=data['message']
        # code=device_data_dict3['code']
        # message=device_data_dict3['message']
        return data
    except base64.binascii.Error as e:
        return {'code':302,'message':data}


def tlsDecodeData(tls_data):
    pass


def decodeSecretDtata(secret_data):
    pass


class AuthenticationServer(protocol.Protocol):
    def __init__(self):
        self.switch = {
            201: self.dhExchange,
            301: self.issueDeviceSecret,
            302: self.normalCommunication
        }

    def dataReceived(self, data):
        code= analyze_rec_data(data)['code']
        data = analyze_rec_data(data)['message']
        print(f"message from Client : {data}")
        sent_data = self.switch[code](data)
        if sent_data:
            self.transport.write(base64.b64encode(pickle.dumps(sent_data)))
        return

    def dhExchange(self, data):
        shared_key = None
        return shared_key

    def issueDeviceSecret(self, data):
        analyze_rec_data(data)

    def normalCommunication(self, data):
        print(f"正在执行normalCommunication")
        data=b'hello client from Server'
        print(f"服务器进行正常通信: {data}")
        return analyze_rec_data(data)


class AuthenticationServerFactory(protocol.Factory):
    def buildProtocol(self, addr):
        return AuthenticationServer()


reactor.listenTCP(8003, AuthenticationServerFactory())
print("Authen Server is running on port 8003")
reactor.run()
