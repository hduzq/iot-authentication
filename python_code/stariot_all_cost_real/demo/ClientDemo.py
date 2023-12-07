from twisted.internet.protocol import Protocol, ClientFactory
from twisted.internet import reactor
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Padding
import json
import base64

SYMMETRIC_KEY = 'ThisIsASecretKey'

class DeviceClientProtocol(Protocol):
    def connectionMade(self):
        # Send Device ID
        device_id = 'MyDeviceID'
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(SYMMETRIC_KEY.encode('utf-8'), AES.MODE_CBC, iv)
        encrypted_device_id = cipher.encrypt(Padding.pad(device_id.encode('utf-8'), AES.block_size))
        self.transport.write(json.dumps({
            'type': 'DEVICE_ID',
            'encrypted_device_id': base64.b64encode(encrypted_device_id).decode('utf-8'),
            'iv': base64.b64encode(iv).decode('utf-8')
        }).encode('utf-8'))
        print("Sent encrypted Device ID")

    def dataReceived(self, data):
        # Receive and decrypt Device Secret
        message = json.loads(data.decode('utf-8'))
        if message['type'] == 'DS':
            iv = base64.b64decode(message['iv'])
            encrypted_ds = base64.b64decode(message['encrypted_ds'])
            cipher = AES.new(SYMMETRIC_KEY.encode('utf-8'), AES.MODE_CBC, iv)
            ds = Padding.unpad(cipher.decrypt(encrypted_ds), AES.block_size).decode('utf-8')
            print(f"Received decrypted Device Secret: {ds}")

class DeviceClientFactory(ClientFactory):
    def buildProtocol(self, addr):
        return DeviceClientProtocol()

reactor.connectTCP("localhost", 8000, DeviceClientFactory())
print("Client is running and connected to localhost:8000")
reactor.run()