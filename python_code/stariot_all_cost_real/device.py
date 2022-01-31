from base64 import *
import socket
from twisted.internet import protocol
from twisted.internet import reactor
import configparser

from utils import *

AS_HOST = LOCALHOST  # the ip of AS
AS_PORT = 9003  # the port of AS
DEVICE_UDP_SERVER_HOST = ''  # the ip of UDP server hosted in the device
DEVICE_UDP_SERVER_PORT = 8001  # the port of UDP server hosted in the device
DEVICE_BIND_TCP_SERVER_HOST = LOCALHOST  # the ip of TCP server hosted in the device in binding mode
DEVICE_BIND_TCP_SERVER_PORT = 9001  # the port of TCP server hosted in the device in binding mode
DEVICE_SAME_TCP_SERVER_PORT = 6001  # the port of local TCP server hosted in the device, used to communicate with app in LAN.

PRODUCT_NAME_BYTES = 4
PRODUCT_SECRET_BYTES = 32
DEVICE_NAME_BYTES = 6
DEVICE_ID_BYTES = PRODUCT_NAME_BYTES + DEVICE_NAME_BYTES
DEVICE_SECRET_BYTES = 32
APP_ID_BYTES = 8
TOKEN_BYTES = 16
KLOCAL_BYTES = 32
RS_ID_BYTES = 16
KDR_BYTES = 32
CONFIG_FILENAME = "device.conf"

KBIND = b'kbind123456789012345678901234567'
bound = True
to_bind = False
to_recover = False
bind_app_id = None
bind_token = None
different_app_id = None
different_info = {}
klocals = {}

logger.name = "DEVICE"


def init_conf():
    config = configparser.ConfigParser()
    config.read(CONFIG_FILENAME)
    return config


config = init_conf()


def read_conf():
    product_name = bytes(config['device']['product_name'], encoding=MY_ENCODING)
    try:
        product_secret = bytes(config['device']['product_secret'], encoding=MY_ENCODING)
    except Exception:
        product_secret = None
        logger.info(Exception)
    device_id = bytes(config['device']['device_id'], encoding=MY_ENCODING)
    try:
        device_secret = b64decode(bytes(config['device']['device_secret'], encoding=MY_ENCODING))
    except Exception:
        device_secret = None
        logger.info(Exception)
    all_sections = config.sections()
    klocals = {}
    for section in all_sections:
        if section != 'device':
            klocals[b64decode(bytes(section, encoding=MY_ENCODING))] = b64decode(
                bytes(config[section]['shared_key'], encoding=MY_ENCODING))
    return [product_name, product_secret, device_id, device_secret, klocals]


PRODUCT_NAME, PRODUCT_SECRET, DEVICE_ID, DEVICE_SECRET, klocals = read_conf()


def is_bound(app_id: bytes) -> bool:
    return config.has_section(str(b64encode(app_id), encoding=MY_ENCODING))


def get_klocal(app_id: bytes) -> bytes:
    return b64decode(config[str(b64encode(app_id), encoding=MY_ENCODING)]['shared_key'])


def update_klocal(app_id: bytes, shared_key: bytes):
    config.set(str(b64encode(app_id), encoding=MY_ENCODING), 'shared_key',
               str(b64encode(shared_key), encoding=MY_ENCODING))
    config.write(open(CONFIG_FILENAME, "w"))


def add_bound(app_id: bytes, shared_key: bytes):
    if not config.has_section(str(b64encode(app_id), encoding=MY_ENCODING)):
        config.add_section(str(b64encode(app_id), encoding=MY_ENCODING))
        config.set(str(b64encode(app_id), encoding=MY_ENCODING), 'shared_key',
                   str(b64encode(shared_key), encoding=MY_ENCODING))
        config.write(open(CONFIG_FILENAME, "w"))


def set_device_secret(device_secret: bytes):
    config.set('device', 'device_secret', str(b64encode(device_secret), encoding=MY_ENCODING))
    config.write(open(CONFIG_FILENAME, "w"))


def delete_product_secret():
    config.remove_option('device', 'product_secret')
    config.write(open(CONFIG_FILENAME, "w"))


def is_activated():
    return config.has_option('device', 'device_secret')


def delete_all_bound():
    for section in config.sections():
        if config.has_option(section, 'shared_key'):
            config.remove_section(section)
    config.write(open(CONFIG_FILENAME, "w"))


class DeviceRegistrationClient(protocol.Protocol):
    def __init__(self):
        self.switch = {
            302: self.activation303
        }
        self.hmac_key = None
        self.activation_info = {}

    def connectionMade(self):
        logger.info('The connection between Device and AS is successful')
        sent_data = self.activation301()
        self.transport.write(sent_data)
        return

    def dataReceived(self, rec_data):
        code, rec_dict = analyze_rec_data(rec_data)
        if verify_message(rec_dict, self.hmac_key):
            sent_data = self.switch[code](rec_dict)
        if sent_data:
            self.transport.write(sent_data)
        return

    def activation301(self):
        """
        device request for DeviceSecret
        """
        r1 = random_16bytes()
        self.activation_info["r1"] = r1
        return compose_data(code=301, other_data=DEVICE_ID, plain_data=DEVICE_ID+r1, enc_key=PRODUCT_SECRET)

    def activation303(self, rec_dict):
        """
        device authenticates hmac, get DS, and confirm to AS
        :param rec_data: str
        """
        decomposed_data = decompose_data(rec_dict, dec_key=PRODUCT_SECRET)
        plain_data, = decomposed_data
        self.activation_info["device_secret"] = plain_data[:DEVICE_SECRET_BYTES]
        r1 = plain_data[DEVICE_SECRET_BYTES:DEVICE_SECRET_BYTES+RANDOM_BYTES]
        r2 = plain_data[DEVICE_SECRET_BYTES+RANDOM_BYTES:]
        if self.activation_info["r1"] == r1:
            set_device_secret(self.activation_info['device_secret'])
            # delete_product_secret()
            logger.info("store DS and delete PS successfully")
            return compose_data(code=303, plain_data=r2, enc_key=self.activation_info["device_secret"])


class DeviceRegistrationClientFactory(protocol.ClientFactory):
    protocol = DeviceRegistrationClient
    clientConnectionLost = clientConnectionFailed = lambda self, connector, reason: reactor.stop()


# the UDP server hosted in the device, waits for a connection from app in LAN
class EchoServer(protocol.DatagramProtocol):
    def __init__(self):
        self.peer_addr = None
        self.switch = {
            601: self.same602
        }

    def startProtocol(self):
        logger.info('device\'s UDP server is running, port is %s' % DEVICE_UDP_SERVER_PORT)
        self.transport.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)

    def datagramReceived(self, rec_data, addr):
        self.peer_addr = addr
        code, rec_dict = analyze_rec_data(rec_data)
        if verify_message(rec_dict):
            sent_data = self.switch[code](rec_dict)
        if sent_data:
            self.transport.write(sent_data, self.peer_addr)
        return

        logger.info("[device\'s UDP server]  receives a message from %s:%s" % addr)
        rec_data = datagram.decode(MY_ENCODING)
        logger.info("[device\'s UDP server]  receives a message: %s" % rec_data)
        start_time = time.time_ns()
        for i in range(LOOP_TIMES):
            rec_json = json.loads(rec_data)
            rec_message = rec_json["message"]
            if rec_message["code"] == 601 and rec_message["device_id"] == DEVICE_ID:
                message = {
                    "code": 602,
                    "device_id": DEVICE_ID
                }
                send_json = {
                    "message": message,
                }
                sent_data = json.dumps(send_json)
        end_time = time.time_ns()
        self.transport.write(sent_data.encode, addr)
        logger.info("time:%s communication_bytes:%s [device's UDP server] sends %s"
                    % (end_time - start_time, len(sent_data.encode), sent_data))

    def same602(self, rec_dict):
        decomposed_data = decompose_data(rec_dict, dec_key=DEVICE_SECRET)
        other_data, = decomposed_data
        if other_data == b'same':
            return compose_data(code=602, other_data=DEVICE_ID)


class DeviceClient(protocol.Protocol):  # the client of the device, communicates with AS
    def __init__(self):
        self.switch = {
            402: self.da_authentication403,
            404: self.da_authentication405,
            506: self.bind508,
            703: self.different706,
            802: self.update803,
            902: self.recover903
        }
        self.hmac_key = None
        self.as_session = {}
        self.recover_info = {}

    def connectionMade(self):
        logger.info('The connection between Device and AS is successful')
        sent_data = self.da_authentication401()
        self.transport.write(sent_data)
        return

    def dataReceived(self, rec_data):
        code, rec_dict = analyze_rec_data(rec_data)
        if verify_message(rec_dict, self.hmac_key):
            sent_data = self.switch[code](rec_dict)
        if sent_data:
            self.transport.write(sent_data)
        return

    def da_authentication401(self):
        """
        The device challenges the AS
        """
        r3 = random_16bytes()
        self.as_session["r3"] = r3
        return compose_data(code=401, other_data=DEVICE_ID, plain_data=r3, enc_key=DEVICE_SECRET)

    def da_authentication403(self, rec_dict):
        """
        device responses to AS, and genereates the session key
        :param rec_data: str
        """
        decomposed_data = decompose_data(rec_dict, dec_key=DEVICE_SECRET)
        plain_data, = decomposed_data
        r3 = plain_data[:RANDOM_BYTES]
        r4 = plain_data[RANDOM_BYTES:]
        self.as_session["r4"] = r4
        if r3 == self.as_session["r3"]:
            return compose_data(code=403, plain_data=r4, enc_key=DEVICE_SECRET)

    def da_authentication405(self, rec_dict):
        decomposed_data = decompose_data(rec_dict)
        other_data, = decomposed_data
        if other_data == b'ok':
            self.as_session["session_key"] = my_hash(self.as_session["r3"] + self.as_session["r4"])
            self.hmac_key = self.as_session["session_key"]
            logger.info("The session key negotiation between Device and AS is successful:{}".format(
                self.as_session["session_key"]))

            if to_bind:
                return compose_data(code=504, plain_data=bind_app_id + bind_token,
                                    enc_key=self.as_session["session_key"])
            elif to_recover:
                return self.recover901()
            else:
                return

    def bind508(self, rec_dict):
        decomposed_data = decompose_data(rec_dict, dec_key=self.as_session["session_key"])
        plain_data, = decomposed_data
        app_id = plain_data[:APP_ID_BYTES]
        klocal = plain_data[APP_ID_BYTES:]
        global to_bind
        to_bind = False
        add_bound(app_id, klocal)
        logger.info("bind successfully with app:%s, store klocal:%s" % (app_id, klocal))
        return

    def different706(self, rec_dict):
        decomposed_data = decompose_data(rec_dict, dec_key=self.as_session["session_key"])
        plain_data, = decomposed_data
        app_id = plain_data[:APP_ID_BYTES]
        rs_id = plain_data[APP_ID_BYTES:APP_ID_BYTES + RS_ID_BYTES]
        kdr = plain_data[APP_ID_BYTES + RS_ID_BYTES:APP_ID_BYTES + RS_ID_BYTES + KDR_BYTES]
        rs_addr_bytes = plain_data[APP_ID_BYTES + RS_ID_BYTES + KDR_BYTES:]

        global different_app_id
        different_app_id = app_id
        rs_ip, rs_port = get_addr_str_int(rs_addr_bytes)
        sent_data_to_rs = compose_data(code=706, other_data=rs_id, plain_data=None, enc_key=None, hmac_key=kdr)
        different_info[app_id] = {
            "rs_id": rs_id,
            "kdr": kdr,
            "connection_data": sent_data_to_rs
        }
        # connect with RS
        reactor.connectTCP(rs_ip, rs_port, DeviceDifferentRSClientFactory())

    def update803(self, rec_dict):
        decomposed_data = decompose_data(rec_dict, dec_key=self.as_session["session_key"])
        plain_data, = decomposed_data
        device_id = plain_data[:DEVICE_ID_BYTES]
        app_id = plain_data[DEVICE_ID_BYTES:DEVICE_ID_BYTES+APP_ID_BYTES]
        r7 = plain_data[DEVICE_ID_BYTES+APP_ID_BYTES:DEVICE_ID_BYTES+APP_ID_BYTES+RANDOM_BYTES]
        old_klocal = plain_data[DEVICE_ID_BYTES+APP_ID_BYTES+RANDOM_BYTES:DEVICE_ID_BYTES+APP_ID_BYTES+RANDOM_BYTES+KLOCAL_BYTES]
        new_klocal = plain_data[DEVICE_ID_BYTES+APP_ID_BYTES+RANDOM_BYTES+KLOCAL_BYTES:]
        if device_id == DEVICE_ID and old_klocal == get_klocal(app_id):
            # update klocal
            update_klocal(app_id, new_klocal)
            klocals[app_id] = new_klocal
            plain_data = app_id + r7
            return compose_data(code=803, plain_data=plain_data, enc_key=self.as_session["session_key"])

    def recover901(self):
        r8 = random_16bytes()
        self.recover_info["random"] = r8
        return compose_data(code=901, plain_data=DEVICE_ID+r8, enc_key=self.as_session["session_key"], hmac_key=self.hmac_key)

    def recover903(self, rec_dict):
        decomposed_data = decompose_data(rec_dict, dec_key=self.as_session["session_key"])
        plain_data, = decomposed_data
        r8 = plain_data
        if self.recover_info["random"] == r8:
            delete_all_bound()
            logger.info("Restore factory settings successfully, and delete user credentials")


class DeviceClientFactory(protocol.ClientFactory):
    protocol = DeviceClient
    clientConnectionLost = clientConnectionFailed = lambda self, connector, reason: reactor.stop()


class DeviceBindServer(protocol.Protocol):
    def __init__(self):
        self.switch = {
            501: self.bind502,
            503: self.bind504
        }
        self.hmac_key = None

    def connectionMade(self):
        logger.info("the address of the client is: {}".format(self.transport.getPeer()))

    def dataReceived(self, rec_data):
        logger.info(rec_data)
        code, rec_dict = analyze_rec_data(rec_data)
        if verify_message(rec_dict, self.hmac_key):
            sent_data = self.switch[code](rec_dict)
        if sent_data:
            self.transport.write(sent_data)
        return

    def bind502(self, rec_dict):
        decomposed_data = decompose_data(rec_dict, dec_key=None)
        other_data, = decomposed_data
        if other_data == b'bind':
            return compose_data(code=502, plain_data=DEVICE_ID, enc_key=KBIND)

    def bind504(self, rec_dict):
        decomposed_data = decompose_data(rec_dict, dec_key=KBIND)
        plain_data, = decomposed_data
        app_id = plain_data[:APP_ID_BYTES]
        token = plain_data[APP_ID_BYTES:]
        global bind_app_id, bind_token
        bind_app_id = app_id
        bind_token = token
        global bound
        if not is_bound(app_id):
            bound = False
            global to_bind
            to_bind = True
            reactor.connectTCP(AS_HOST, AS_PORT, DeviceClientFactory())
        else:
            bound = True
            logger.info('app has bound me')


class DeviceBindServerFactory(protocol.Factory):
    protocol = DeviceBindServer


class DeviceSameServer(protocol.Protocol):
    def __init__(self):
        self.switch = {
            603: self.same604,
            605: self.same606,
            608: self.same609
        }
        self.app_session = {}
        self.klocal = None
        self.hmac_key = None

    def connectionMade(self):
        logger.info("In LAN, the address of the client is: {}".format(self.transport.getPeer()))

    def dataReceived(self, rec_data):
        code, rec_dict = analyze_rec_data(rec_data)
        if verify_message(rec_dict, self.hmac_key):
            sent_data = self.switch[code](rec_dict)
        if sent_data:
            self.transport.write(sent_data)
        return

    def same604(self, rec_dict):
        app_id = rec_dict[OTHER_DATA]
        klocal = klocals[app_id]
        self.klocal = klocal
        decomposed_data = decompose_data(rec_dict, dec_key=klocal)
        other_data, plain_data, = decomposed_data
        r5 = plain_data
        r6 = random_16bytes()
        self.app_session["r5"] = r5
        self.app_session["r6"] = r6
        return compose_data(code=604, plain_data=r5 + r6, enc_key=klocal)

    def same606(self, rec_dict):
        decomposed_data = decompose_data(rec_dict, dec_key=self.klocal)
        plain_data, = decomposed_data
        r6 = plain_data
        if self.app_session["r6"] == r6:
            self.app_session["session_key"] = my_hash(self.app_session["r5"] + r6)
            self.hmac_key = self.app_session["session_key"]
            return compose_data(code=606, plain_data=b'same ok', enc_key=self.app_session["session_key"])

    def same609(self, rec_dict):
        decomposed_data = decompose_data(rec_dict, dec_key=self.app_session["session_key"])
        plain_data, = decomposed_data
        message = plain_data
        logger.info("收到业务消息{message}".format(message=message))
        return compose_data(code=609, plain_data=M2, enc_key=self.app_session["session_key"],
                            hmac_key=self.app_session["session_key"])


class DeviceSameServerFactory(protocol.Factory):
    protocol = DeviceSameServer


class DeviceDifferentRSClient(protocol.Protocol):
    def __init__(self):
        self.different_app_id = different_app_id
        self.session_key = different_info[self.different_app_id]["kdr"]
        self.hmac_key = self.session_key
        self.rs_id = different_info[self.different_app_id]["rs_id"]
        self.connection_data = different_info[self.different_app_id]["connection_data"]
        self.switch = {
            708: self.different709,
            712: self.different713
        }

    def connectionMade(self):
        self.transport.write(self.connection_data)
        logger.info("device sends %s to RS" % self.connection_data)

    def dataReceived(self, rec_data):
        code, rec_dict = analyze_rec_data(rec_data)
        if verify_message(rec_dict, self.hmac_key):
            sent_data = self.switch[code](rec_dict)
        if sent_data:
            self.transport.write(sent_data)
        return

    def connectionLost(self, reason):
        logger.info('the server is closed')

    def different709(self, rec_dict):
        decomposed_data = decompose_data(rec_dict, dec_key=self.session_key)
        plain_data, = decomposed_data
        if plain_data == b'different ok':
            logger.info('connects with RS successfully')

    def different713(self, rec_dict):
        decomposed_data = decompose_data(rec_dict, dec_key=self.session_key)
        plain_data, = decomposed_data
        message = plain_data
        logger.info("收到业务消息{message}".format(message=message))
        return compose_data(code=713, plain_data=M4, enc_key=self.session_key, hmac_key=self.hmac_key)


class DeviceDifferentRSClientFactory(protocol.ClientFactory):
    protocol = DeviceDifferentRSClient
    clientConnectionLost = clientConnectionFailed = lambda self, connector, reason: reactor.stop()


def main():
    mode = input("please choose the mode, 1: activation 2:bind 3:communication 4:restore factory setting ")
    if mode == '1':
        reactor.connectTCP(AS_HOST, AS_PORT, DeviceRegistrationClientFactory())
    elif mode == '2':
        reactor.listenTCP(DEVICE_BIND_TCP_SERVER_PORT, DeviceBindServerFactory())
    elif mode == '3':
        reactor.listenTCP(DEVICE_SAME_TCP_SERVER_PORT, DeviceSameServerFactory())
        reactor.listenUDP(DEVICE_UDP_SERVER_PORT, EchoServer(), DEVICE_UDP_SERVER_HOST)
        logger.info("device's UDP server is running")
        reactor.connectTCP(AS_HOST, AS_PORT, DeviceClientFactory())
    elif mode == '4':
        global to_recover
        to_recover = True
        reactor.connectTCP(AS_HOST, AS_PORT, DeviceClientFactory())
    reactor.run()

    # issuing device key
    # reactor.connectTCP(AS_HOST, AS_PORT, DeviceRegistrationClientFactory())

    # communication with AS
    # reactor.connectTCP(AS_HOST, AS_PORT, DeviceClientFactory())

    # bind
    # reactor.listenTCP(DEVICE_BIND_TCP_SERVER_PORT, DeviceBindServerFactory())

    # same
    # reactor.listenUDP(DEVICE_UDP_SERVER_PORT, EchoServer(), DEVICE_UDP_SERVER_HOST)
    # reactor.listenTCP(DEVICE_SAME_TCP_SERVER_PORT, DeviceSameServerFactory())

    # different
    # reactor.connectTCP(AS_HOST, AS_PORT, DeviceClientFactory())

    # reactor.run()


if __name__ == '__main__':
    main()
