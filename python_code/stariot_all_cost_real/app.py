from base64 import *
from twisted.internet import protocol
from twisted.internet import reactor
import configparser
from socket import SOL_SOCKET, SO_BROADCAST

from utils import *

AS_HOST = LOCALHOST  # the ip of AS
AS_PORT = 9003  # the port of AS
DEVICE_UDP_SERVER_PORT = 8001  # the port of device's UDP server
DEVICE_BIND_TCP_SERVER_HOST = LOCALHOST  # the ip of TCP server hosted in the device in binding mode
DEVICE_BIND_TCP_SERVER_PORT = 9001  # the port of TCP server hosted in the device in binding mode
BROADCAST_HOST = '255.255.255.255'
DEVICE_SAME_TCP_SERVER_PORT = 6001  # the local TCP server hosted in the device, communicating with app in LAN

PRODUCT_NAME_BYTES = 4
DEVICE_NAME_BYTES = 6
DEVICE_ID_BYTES = PRODUCT_NAME_BYTES + DEVICE_NAME_BYTES
APP_ID_BYTES = 8
RS_ID_BYTES = 16
KRP_BYTES = 32
SALT_BYTES = 16
DELTA_TIME = 3
LOOP_TIMES = 1

KBIND = b'kbind123456789012345678901234567'
KAP = b'kap12345678901234567890123456789'
APP_ID = b'iamappjj'
username = b'1234567890123456'
password = b'1234567890123456'
update_mode = False
new_username = b'1234567890123456'
new_password = b'1234567890123456'
bind_info = {}  # store device_id and token
bind_request_as = False
different_device_id = None
different_info = {}
bound_devices_id = []
devices_salt = {}
CONFIG_FILENAME = "app.conf"

# username = b'starstarstarstar'
# password = b'haha'
# new_username = b'my_new_username'
# new_password = b'my_new_password'

logger.name = 'APP'


def init_conf():
    myconfig = configparser.ConfigParser()
    myconfig.read(CONFIG_FILENAME)
    return myconfig


config = init_conf()


def get_bound(device_id):
    return config.has_section(device_id)


def set_bound(device_id, salt):
    device_id = str(b64encode(device_id), encoding=MY_ENCODING)
    salt = str(b64encode(salt), encoding=MY_ENCODING)
    if not config.has_section(device_id):
        config.add_section(device_id)
        config.write(open(CONFIG_FILENAME, "w"))
        config.set(device_id, 'salt', salt)
        config.write(open(CONFIG_FILENAME, "w"))


def update_salt(device_id, salt):
    device_id = str(b64encode(device_id), encoding=MY_ENCODING)
    salt = str(b64encode(salt), encoding=MY_ENCODING)
    if config.has_section(device_id):
        config.set(device_id, 'salt', salt)
        config.write(open(CONFIG_FILENAME, "w"))


def get_salts():
    all_sections = config.sections()
    all_devices_salt = {}
    for section in all_sections:
        device_id = b64decode(bytes(section, encoding=MY_ENCODING))
        all_devices_salt[device_id] = b64decode(bytes(config[section]['salt'], encoding=MY_ENCODING))
    return all_devices_salt


def get_bound_devices_id() -> list:
    return [b64decode(bytes(section, encoding=MY_ENCODING)) for section in config.sections()]


bound_devices_id = get_bound_devices_id()
devices_salt = get_salts()
lan_device_id = None


class AppBindClient(protocol.Protocol):
    def __init__(self):
        self.switch = {
            502: self.bind503,
            507: self.bind509
        }
        self.as_session = {}
        self.hmac_key = None

    def connectionMade(self):
        logger.info('connects with device successfully, the device is: %s' % self.transport.getPeer())
        # start_time = time.time_ns()
        if bind_request_as:
            # suppose app sleep 3 seconds
            time.sleep(3)
            for i in range(LOOP_TIMES):
                sent_data = self.bind505()
        else:
            for i in range(LOOP_TIMES):
                sent_data = self.bind501()
        # end_time = time.time_ns()
        # logger.info("time:%s communication_bytes:%s device_server sends %s"
        #             % (end_time - start_time, len(sent_data.encode), sent_data))
        self.transport.write(sent_data)

    def dataReceived(self, rec_data):
        logger.info(rec_data)
        code, rec_dict = analyze_rec_data(rec_data)
        if verify_message(rec_dict, self.hmac_key):
            sent_data = self.switch[code](rec_dict)
        if sent_data:
            self.transport.write(sent_data)
            if bind_request_as == True:
                # send a request to AS for binding device
                reactor.connectTCP(AS_HOST, AS_PORT, AppBindClientFactory())
        return

    def bind501(self):
        return compose_data(code=501, other_data=b'bind')

    def bind503(self, rec_dict):
        decomposed_data = decompose_data(rec_dict, dec_key=KBIND)
        plain_data, = decomposed_data
        device_id = plain_data
        if device_id in bound_devices_id:
            logger.info("has bound device: %s" % device_id)
            rebind_flag = True
            if rebind_flag:
                logger.info("to bind the device: %s again" % device_id)
            else:
                logger.info("do not bind the device: %s twice" % device_id)
                return
        token = random_16bytes()
        bind_info["device_id"] = device_id
        bind_info["token"] = token
        global bind_request_as
        bind_request_as = True
        return compose_data(code=503, plain_data=APP_ID + token, enc_key=KBIND)

    def bind505(self):
        return compose_data(code=505,
                            plain_data=bind_info["device_id"] + APP_ID + bind_info["token"] + username + my_hash(
                                password), enc_key=KAP)

    def bind509(self, rec_dict):
        decomposed_data = decompose_data(rec_dict, dec_key=KAP)
        plain_data, = decomposed_data
        device_id = plain_data[:DEVICE_ID_BYTES]
        salt = plain_data[DEVICE_ID_BYTES:]
        if device_id in bind_info.values():
            # logger.info("bind the device:%s successfully" % device_id)
            pass
        set_bound(device_id, salt)
        logger.info("bind the device:%s successfully" % device_id)
        global bind_request_as
        bind_request_as = False
        return


class AppBindClientFactory(protocol.ClientFactory):
    protocol = AppBindClient
    clientConnectionLost = clientConnectionFailed = lambda self, connector, reason: \
        reactor.stop()


class EchoClientDatagramProtocol(protocol.DatagramProtocol):

    def startProtocol(self):
        self.transport.socket.setsockopt(SOL_SOCKET, SO_BROADCAST, True)
        self.sendDatagram()

    def sendDatagram(self):
        sent_data = compose_data(code=601, other_data=b'same')
        self.transport.write(sent_data, (BROADCAST_HOST, DEVICE_UDP_SERVER_PORT))
        return

        start_time = time.time_ns()
        for i in range(LOOP_TIMES):
            sent_data = compose_data(code=601, other_data=b'same')
        end_time = time.time_ns()
        logger.info("time:%s communication_bytes:%s app sends a broadcast package to discover the device"
                    % (end_time - start_time, len(sent_data.encode)))
        self.transport.write(sent_data.encode, (BROADCAST_HOST, DEVICE_UDP_SERVER_PORT))

    def datagramReceived(self, rec_data, addr):
        code, rec_dict = analyze_rec_data(rec_data)
        decomposed_data = decompose_data(rec_dict)
        other_data, = decomposed_data
        device_id = other_data
        if code == 602 and device_id in bound_devices_id:
            global lan_device_id
            lan_device_id = device_id
            reactor.connectTCP(addr[0], DEVICE_SAME_TCP_SERVER_PORT, AppSameClientFactory())
        return


class AppSameClient(protocol.Protocol):
    def __init__(self):
        self.switch = {
            604: self.same605,
            606: self.same607,
            609: self.same610
        }
        self.device_session = {}
        self.klocal = None
        self.hmac_key = None

    def connectionMade(self):
        logger.info("connects with the local tcp server hosted in the device successfully: {}"
                    .format(self.transport.getPeer()))
        start_time = time.time_ns()
        for i in range(LOOP_TIMES):
            sent_data = self.same603()
        end_time = time.time_ns()
        logger.info('time:%s communication_bytes:%s[TCP client] sends the local tcp server hosted in the device: %s'
                    % (end_time - start_time, len(sent_data), sent_data))
        self.transport.write(sent_data)

    def dataReceived(self, rec_data):
        code, rec_dict = analyze_rec_data(rec_data)
        if verify_message(rec_dict, hmac_key=self.hmac_key):
            sent_data = self.switch[code](rec_dict)
        if sent_data:
            self.transport.write(sent_data)
        return

    def same603(self):
        salt = devices_salt[bound_devices_id[0]]  # suppose to communicate with the first bound device in LAN
        self.klocal = my_hash(lan_device_id + APP_ID + username + my_hash(salt + my_hash(password)))
        r5 = random_16bytes()
        self.device_session["r5"] = r5
        return compose_data(code=603, other_data=APP_ID, plain_data=r5, enc_key=self.klocal)

    def same605(self, rec_dict):
        decomposed_data = decompose_data(rec_dict, dec_key=self.klocal)
        plain_data, = decomposed_data
        r5 = plain_data[:RANDOM_BYTES]
        r6 = plain_data[RS_ID_BYTES:]
        self.device_session["session_key"] = my_hash(r5 + r6)
        self.hmac_key = self.device_session["session_key"]
        if r5 == self.device_session["r5"]:
            return compose_data(code=605, plain_data=r6, enc_key=self.klocal)

    def same607(self, rec_dict):
        decomposed_data = decompose_data(rec_dict, dec_key=self.device_session["session_key"])
        plain_data, = decomposed_data
        if plain_data == b'same ok':
            return self.same608()

    def same608(self):
        return compose_data(code=608, plain_data=M1, enc_key=self.device_session["session_key"],
                            hmac_key=self.device_session["session_key"])

    def same610(self, rec_dict):
        decomposed_data = decompose_data(rec_dict, dec_key=self.device_session["session_key"])
        plain_data, = decomposed_data
        message = plain_data
        logger.info("收到业务消息{message}".format(message=message))
        return


class AppSameClientFactory(protocol.ClientFactory):
    protocol = AppSameClient
    clientConnectionLost = clientConnectionFailed = lambda self, connector, reason: \
        reactor.stop()


class AppDifferentASClient(protocol.Protocol):
    def __init__(self):
        self.switch = {
            704: self.different707,
            804: self.update805
        }
        self.update_info = {}
        self.hmac_key = KAP

    def connectionMade(self):
        logger.info("connects with AS successfully: {}".format(self.transport.getPeer()))
        start_time = time.time_ns()
        for i in range(LOOP_TIMES):
            if update_mode:
                sent_data = self.update801()
            else:
                sent_data = self.different701()
        end_time = time.time_ns()
        logger.info('time:%s communication_bytes:%s[tcp client] sends %s'
                    % (end_time - start_time, len(sent_data), sent_data))
        self.transport.write(sent_data)

    def dataReceived(self, rec_data):
        code, rec_dict = analyze_rec_data(rec_data)
        if verify_message(rec_dict, self.hmac_key):
            sent_data = self.switch[code](rec_dict)
        if sent_data:
            self.transport.write(sent_data)
        return

    def different701(self):
        # suppose APP wants to communicate with the first device in public network
        return compose_data(code=701, plain_data=bound_devices_id[0] + APP_ID + username + my_hash(password),
                            enc_key=KAP, hmac_key=KAP)

    def different707(self, rec_dict):
        decomposed_data = decompose_data(rec_dict, dec_key=KAP)
        plain_data, = decomposed_data
        device_id = plain_data[:DEVICE_ID_BYTES]
        rs_id = plain_data[DEVICE_ID_BYTES:DEVICE_ID_BYTES + RS_ID_BYTES]
        krp = plain_data[DEVICE_ID_BYTES + RS_ID_BYTES:DEVICE_ID_BYTES + RS_ID_BYTES + KRP_BYTES]
        rs_addr_bytes = plain_data[DEVICE_ID_BYTES + RS_ID_BYTES + KRP_BYTES:]

        global different_device_id
        different_device_id = device_id
        rs_ip, rs_port = get_addr_str_int(rs_addr_bytes)
        sent_data_to_rs = compose_data(code=707, other_data=rs_id, plain_data=None, enc_key=None, hmac_key=krp)
        different_info[device_id] = {
            "rs_id": rs_id,
            "krp": krp,
            "connection_data": sent_data_to_rs
        }
        # run the client communicating with RS
        reactor.connectTCP(rs_ip, rs_port, AppDifferentRSClientFactory())

    def update801(self):
        r7 = random_16bytes()
        self.update_info["random"] = r7
        self.update_info["device_id"] = bound_devices_id[0]
        # ready to update the user credential of the first device
        plain_data = self.update_info["device_id"] + APP_ID + r7 + username + SPECIAL_BYTE + my_hash(
            password) + new_username + SPECIAL_BYTE + my_hash(new_password)
        return compose_data(code=801, plain_data=plain_data, enc_key=KAP, hmac_key=KAP)

    def update805(self, rec_dict):
        decomposed_data = decompose_data(rec_dict, dec_key=KAP)
        plain_data, = decomposed_data
        r7 = plain_data[:RANDOM_BYTES]
        new_salt = plain_data[RANDOM_BYTES:]
        if self.update_info["random"] == r7:
            update_salt(self.update_info["device_id"], new_salt)
            devices_salt[self.update_info["device_id"]] = new_salt
            logger.info("更新凭证成功")


class AppDifferentASClientFactory(protocol.ClientFactory):
    protocol = AppDifferentASClient
    clientConnectionLost = clientConnectionFailed = lambda self, connector, reason: \
        reactor.stop()


class AppDifferentRSClient(protocol.Protocol):
    def __init__(self):
        self.different_device_id = different_device_id
        self.session_key = different_info[self.different_device_id]["krp"]
        self.hmac_key = self.session_key
        self.rs_id = different_info[self.different_device_id]["rs_id"]
        self.connection_data = different_info[self.different_device_id]["connection_data"]
        self.switch = {
            710: self.different711,
            714: self.different715
        }

    def connectionMade(self):
        self.transport.write(self.connection_data)  # connects with RS

    def dataReceived(self, rec_data):
        code, rec_dict = analyze_rec_data(rec_data)
        if verify_message(rec_dict, self.hmac_key):
            sent_data = self.switch[code](rec_dict)
        if sent_data:
            self.transport.write(sent_data)
        return

    def connectionLost(self, reason):
        logger.info('the server is closed')

    def different711(self, rec_dict):
        decomposed_data = decompose_data(rec_dict, dec_key=self.session_key)
        plain_data, = decomposed_data
        if plain_data == b'different ok':
            logger.info('connects with RS successfully, then sends a message to RS')
            return compose_data(code=711, plain_data=M3, enc_key=self.session_key, hmac_key=self.hmac_key)

    def different715(self, rec_dict):
        decomposed_data = decompose_data(rec_dict, dec_key=self.session_key)
        plain_data, = decomposed_data
        message = plain_data
        logger.info("收到业务消息{message}".format(message=message))


class AppDifferentRSClientFactory(protocol.ClientFactory):
    protocol = AppDifferentRSClient
    clientConnectionLost = clientConnectionFailed = lambda self, connector, reason: reactor.stop()


def main():
    mode = input(
        "Please choose the mode, 1:bind 2:communication in LAN 3:communication in public network 4:update the credential")
    if mode == '1':
        reactor.connectTCP(DEVICE_BIND_TCP_SERVER_HOST, DEVICE_BIND_TCP_SERVER_PORT, AppBindClientFactory())
    elif mode == '2':
        reactor.listenUDP(0, EchoClientDatagramProtocol())
    elif mode == '3':
        reactor.connectTCP(AS_HOST, AS_PORT, AppDifferentASClientFactory())
    elif mode == '4':
        global update_mode
        update_mode = True
        reactor.connectTCP(AS_HOST, AS_PORT, AppDifferentASClientFactory())
    reactor.run()

    # bind
    # reactor.connectTCP(DEVICE_BIND_TCP_SERVER_HOST, DEVICE_BIND_TCP_SERVER_PORT, AppBindClientFactory())

    # same
    # reactor.listenUDP(0, EchoClientDatagramProtocol())

    # different
    # reactor.connectTCP(AS_HOST, AS_PORT, AppDifferentASClientFactory())

    # update
    # global update_mode
    # update_mode = True
    # reactor.connectTCP(AS_HOST, AS_PORT, AppDifferentASClientFactory())

    # reactor.run()


if __name__ == '__main__':
    main()
