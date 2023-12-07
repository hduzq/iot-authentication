import base64
import pickle
from base64 import *
from twisted.internet import protocol
from twisted.internet import reactor

from python_code.stariot_all_cost_real.communicationDemo.DataDemo import *


def composeDeviceData():
    pass

def analyze_rec_data(data):
    '''解析data，用于区分数据类型一进行下一步判断'''
    # tls_data = pickle.loads(data)
    # secret_data = tlsDecodeData(tls_data)
    # code =secret_data[code]
    # plain_data = decodeSecretDtata(secret_data)
    # plain_data = b'hello'
    print("client产生的消息")
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
class Device(protocol.Protocol):

    def __init__(self):
        self.switch = {
            302: self.normalCommunication
        }
    def connectionMade(self):
        compose_device_data=composeDeviceData()

        self.transport.write(base64.b64encode(pickle.dumps(device_data_dict3)))

    def dataReceived(self, data: bytes):
        code = analyze_rec_data(data)['code']
        data = analyze_rec_data(data)['message']
        print(f"message from Server: {data}")
        sent_data = self.switch[code](data)
        if sent_data:
            self.transport.write(base64.b64encode(pickle.dumps(sent_data)))
        return

    def normalCommunication(self,data):

        data=b'hello server ---Client'
        print(f"客户端进行正常通信: {data}")
        return analyze_rec_data(data)
class DeviceFactory(protocol.ClientFactory):

    def buildProtocol(self,addr):
        return Device()


reactor.connectTCP("localhost",8003,DeviceFactory())
print("Client is running and connected to localhost:8003")
reactor.run()