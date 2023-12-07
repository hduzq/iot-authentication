from twisted.internet.protocol import ClientFactory
from twisted.protocols.basic import LineReceiver
from twisted.internet import reactor
from Crypto.PublicKey import DH
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

product_secret = b"product_secret"  # hard-coded product_secret
device_id = b"MyDeviceID"  # hard-coded device_id

class SecureChannel(LineReceiver):
    def __init__(self):
        self.dh = DH.generate(1024)
        self.shared_key = None

    def connectionMade(self):
        self.sendLine(base64.b64encode(self.dh.publickey().exportKey()).decode())

    def lineReceived(self, line):
        if self.shared_key is None:
            peer_public_key = DH.importKey(base64.b64decode(line))
            self.shared_key = self.dh.generate_shared_secret(peer_public_key)
            cipher = AES.new(self.shared_key[:16], AES.MODE_CBC)
            encrypted_device_id = cipher.encrypt(pad(device_id, AES.block_size))
            self.sendLine(base64.b64encode(encrypted_device_id).decode())
        else:
            print(f"Received: {line.decode()}")

class SecureChannelFactory(ClientFactory):
    def buildProtocol(self, addr):
        return SecureChannel()

if __name__ == "__main__":
    reactor.connectTCP("localhost", 1234, SecureChannelFactory())
    reactor.run()