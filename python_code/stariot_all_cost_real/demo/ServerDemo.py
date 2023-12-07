from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Padding
import json
import base64

#todo: 对整个message利用dh协商后的密钥进行通信
SYMMETRIC_KEY = 'ThisIsASecretKey'

class DeviceServerProtocol(Protocol):
    def dataReceived(self, data):
        # Receive and decrypt Device ID
        message = json.loads(data.decode('utf-8'))
        if message['type'] == 'DEVICE_ID':
            iv = base64.b64decode(message['iv'])
            encrypted_device_id = base64.b64decode(message['encrypted_device_id'])
            cipher = AES.new(SYMMETRIC_KEY.encode('utf-8'), AES.MODE_CBC, iv)
            device_id = Padding.unpad(cipher.decrypt(encrypted_device_id), AES.block_size).decode('utf-8')
            print(f"Received decrypted Device ID: {device_id}")

            # Send Device Secret
            ds = 'DeviceSecret'
            iv = Random.new().read(AES.block_size)
            cipher = AES.new(SYMMETRIC_KEY.encode('utf-8'), AES.MODE_CBC, iv)
            encrypted_ds = cipher.encrypt(Padding.pad(ds.encode('utf-8'), AES.block_size))
            print(cipher)
            self.transport.write(json.dumps({
                'type': 'DS',
                'encrypted_ds': base64.b64encode(encrypted_ds).decode('utf-8'),
                'iv': base64.b64encode(iv).decode('utf-8')
            }).encode('utf-8'))
            print("Sent encrypted Device Secret")

class DeviceServerFactory(Factory):
    def buildProtocol(self, addr):
        return DeviceServerProtocol()

reactor.listenTCP(8000, DeviceServerFactory())
print("Server is running on port 8000")
reactor.run()