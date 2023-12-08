from twisted.internet import protocol, reactor
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import pickle
import base64

# 服务器端和客户端
device_secret = b"device_secret_here"
product_secret = b"product_secret_here"


def load_parameters():
    with open('parameters.pkl', 'rb') as f:
        p, g = pickle.load(f)
    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters(default_backend())
    return parameters


parameters = load_parameters()
print(parameters)  # 可以对parameters进行任何你需要的操作


class Echo(protocol.Protocol):
    def __init__(self):
        self.private_key = parameters.generate_private_key()
        self.data = b""

    def connectionMade(self):
        # 将公钥序列化并发送给客户端
        public_key_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.transport.write(base64.b64encode(public_key_bytes) + b'\n')

    def dataReceived(self, data):
        self.data += data
        if b'\n' in self.data:
            line, self.data = self.data.split(b'\n', 1)
            client_public_key = base64.b64decode(line).rstrip(b'\n')

            client_public_key = serialization.load_pem_public_key(client_public_key, backend=default_backend())

            shared_key = self.private_key.exchange(client_public_key)
            print(f"shared_key : {shared_key}")
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"handshake data",
                backend=default_backend()).derive(shared_key)
            cipher_suite = Fernet(base64.urlsafe_b64encode(derived_key))
            encrypted_message = cipher_suite.encrypt(device_secret)
            self.transport.write(base64.b64encode(encrypted_message) + b'\n')


class EchoFactory(protocol.Factory):
    def buildProtocol(self, addr):
        return Echo()


reactor.listenTCP(8000, EchoFactory())
reactor.run()
