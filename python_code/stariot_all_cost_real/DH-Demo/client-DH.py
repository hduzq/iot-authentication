from twisted.internet import protocol, reactor
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import pickle

product_secret = b"product_secret_here"

#加载相同的parameters
def load_parameters():
    with open('parameters.pkl', 'rb') as f:
        p, g = pickle.load(f)
    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters(default_backend())
    return parameters

parameters = load_parameters()
print(parameters)  # 可以对parameters进行任何你需要的操作

class EchoClient(protocol.Protocol):
    def __init__(self):
        self.private_key = parameters.generate_private_key()
        self.data = b""

    def connectionMade(self):
        # 将公钥序列化并发送给服务器
        public_key_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.transport.write(base64.b64encode(public_key_bytes) + b'\n')

    def dataReceived(self, data):
        self.data += data
        if b'\n' in self.data:
            line, self.data = self.data.split(b'\n', 1)
            server_public_key = base64.b64decode(line)
            server_public_key = serialization.load_pem_public_key(server_public_key, backend=default_backend())

            shared_key = self.private_key.exchange(server_public_key)
            print(f"shared_key : {shared_key}")
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"handshake data",
                backend=default_backend()).derive(shared_key)
            cipher_suite = Fernet(base64.urlsafe_b64encode(derived_key))
            encrypted_message = cipher_suite.encrypt(product_secret)
            self.transport.write(base64.b64encode(encrypted_message) + b'\n')


class EchoClientFactory(protocol.ClientFactory):
    def buildProtocol(self, addr):
        return EchoClient()


reactor.connectTCP("localhost", 8000, EchoClientFactory())
reactor.run()
