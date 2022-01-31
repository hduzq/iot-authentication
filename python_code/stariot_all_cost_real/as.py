from base64 import *
from twisted.internet import protocol
from twisted.internet import reactor
import pymysql
import re

from utils import *

AS_PORT = 9003  # the port of AS
RS_HOST = LOCALHOST  # the ip of RS
RS_PORT = 9002  # the port of RS
RS_ADDR_BYTES = get_addr_bytes(RS_HOST, RS_PORT)

KAP = b'kap12345678901234567890123456789'
KRA = b'kra12345678901234567890123456789'

APP_ID_BYTES = 8
TOKEN_BYTES = 16
PRODUCT_NAME_BYTES = 4
DEVICE_NAME_BYTES = 6
DEVICE_ID_BYTES = PRODUCT_NAME_BYTES + DEVICE_NAME_BYTES
DELTA_TIME = 3

sockets = {}  # store the sockets of devices and apps, keys are device_id or app_id
to_rs_socket = None
bind_info = {}  # key is device_id, value is a dictionary with app_id, token and Kda
update_info = {}  # key is app_id, stores R, new_username, new_hash_password
rs_ids = []  # store all rs_id
logger.name = "AS"


class AuthServer(protocol.Protocol):
    def __init__(self):
        self.connection = None
        self.cursor = None
        self.init_db()
        self.switch = {
            301: self.activation302,
            303: self.activation304,
            401: self.da_authentication402,
            403: self.da_authentication404,
            504: self.bind504,
            505: self.bind507,
            701: self.different702,
            801: self.update802,
            803: self.update804,
            901: self.recover902
        }
        self.activation_info = {}
        self.device_session = {}
        self.hmac_key = None
        self.app_session = {"session_key": KAP}

    def init_db(self):
        self.connection = pymysql.connect(
            host="localhost",
            user='root',
            password='123456',
            database='as',
            charset='utf8'
        )
        self.cursor = self.connection.cursor()

    def connectionMade(self):
        logger.info("the address of the client is: {}".format(self.transport.getPeer()))

    def dataReceived(self, rec_data):
        logger.info(rec_data)
        code, rec_dict = analyze_rec_data(rec_data)
        sent_data = self.switch[code](rec_dict)
        if sent_data:
            # logger.info('communication_bytes:%s AS sends %s' % (len(sent_data.encode), sent_data))
            self.transport.write(sent_data)
        return

    def activation302(self, rec_dict):
        """
        AS issues DeviceSecret
        :param rec_data: str
        """
        other_data = rec_dict[OTHER_DATA]
        device_id = other_data[:DEVICE_ID_BYTES]
        product_name = device_id[:PRODUCT_NAME_BYTES]
        self.cursor.execute("select product_secret from product where product_name=%s", args=product_name)
        product_secret = self.cursor.fetchone()[0]  # bytes
        decomposed_data = decompose_data(rec_dict, dec_key=product_secret)
        other_data, plain_data, = decomposed_data
        r1 = plain_data[DEVICE_ID_BYTES:]
        if device_id == plain_data[:DEVICE_ID_BYTES]:
            device_secret = random_32bytes()
            r2 = random_16bytes()
            self.activation_info = {
                "device_id": device_id,
                "device_secret": device_secret,
                "r2": r2
            }
            return compose_data(code=302, plain_data=device_secret+r1+r2, enc_key=product_secret)

    def activation304(self, rec_dict):
        """
        AS confirms if device get the DS, if successful, it will update DS and inform device.
        :param rec_data: str
        """
        decomposed_data = decompose_data(rec_dict, dec_key=self.activation_info["device_secret"])
        plain_data, = decomposed_data
        r2 = plain_data[:RANDOM_BYTES]
        if self.activation_info["r2"] == r2:
            self.cursor.execute('update device set device_secret=%s where device_id=%s',
                                args=(self.activation_info["device_secret"], self.activation_info["device_id"]))
            self.connection.commit()
            return

    def da_authentication402(self, rec_dict):
        """
        AS responses r4 from device and issues challenge r5
        :param rec_data: str
        """
        device_id = rec_dict[OTHER_DATA]
        self.cursor.execute("select device_secret from device where device_id=%s", args=device_id)
        device_secret = self.cursor.fetchone()[0]  # bytes
        self.device_session["device_id"] = device_id
        self.device_session["device_secret"] = device_secret

        decomposed_data = decompose_data(rec_dict, dec_key=device_secret)
        other_data, plain_data, = decomposed_data
        r3 = plain_data
        r4 = random_16bytes()
        self.device_session["r3"] = r3
        self.device_session["r4"] = r4
        return compose_data(code=402, plain_data=r3 + r4, enc_key=device_secret)

    def da_authentication404(self, rec_dict):
        """
        AS confirms if device responses successfully, if successful, he will generate the session key.
        :param rec_data: str
        """
        decomposed_data = decompose_data(rec_dict, dec_key=self.device_session["device_secret"])
        plain_data, = decomposed_data
        r4 = plain_data
        if r4 == self.device_session["r4"]:
            self.device_session["session_key"] = my_hash(self.device_session["r3"] + self.device_session["r4"])
            self.hmac_key = self.device_session["session_key"]
            global sockets
            sockets[self.device_session["device_id"]] = self
            logger.info("The session key negotiation between AS and Device is successful, session key is: {}"
                        .format(self.device_session["session_key"]))
            return compose_data(code=404, other_data=b'ok')

    def bind504(self, rec_dict):
        decomposed_data = decompose_data(rec_dict, dec_key=self.device_session["session_key"])
        plain_data, = decomposed_data
        app_id = plain_data[:APP_ID_BYTES]
        token = plain_data[APP_ID_BYTES:]
        bind_info[self.device_session["device_id"]] = {
            "session_key": self.device_session["session_key"],
            "app_id": app_id,
            "token": token
        }

    def bind506(self, device_id, sent_data):
        sockets[device_id].transport.write(sent_data)
        return

    def bind507(self, rec_dict):
        decomposed_data = decompose_data(rec_dict, dec_key=self.app_session["session_key"])
        plain_data, = decomposed_data
        device_id = plain_data[:DEVICE_ID_BYTES]
        app_id = plain_data[DEVICE_ID_BYTES:DEVICE_ID_BYTES+APP_ID_BYTES]
        token = plain_data[DEVICE_ID_BYTES+APP_ID_BYTES:DEVICE_ID_BYTES+APP_ID_BYTES+TOKEN_BYTES]
        username_bytes = plain_data[DEVICE_ID_BYTES+APP_ID_BYTES+TOKEN_BYTES:-HASH_SHA256_BYTES]
        username_str = str(username_bytes, encoding=MY_ENCODING)
        hash_password = plain_data[-HASH_SHA256_BYTES:]
        if device_id in bind_info and bind_info[device_id]["app_id"] == app_id and bind_info[device_id]["token"] == token:
            salt = create_salt()
            salted_hash_password = my_hash(salt + hash_password)
            klocal = my_hash(device_id+app_id+username_bytes+salted_hash_password)

            # store app_id into database
            self.cursor.execute('select count(*) from app where app_id=%s', args=bind_info[device_id]["app_id"])
            result = self.cursor.fetchone()[0]
            if result == 0:
                self.cursor.execute('insert into app(app_id) values(%s)',
                                    args=bind_info[device_id]["app_id"])
                self.connection.commit()
            self.cursor.execute('select count(*) from bind where device_id=%s and app_id=%s',
                                args=(device_id, bind_info[device_id]["app_id"]))
            result = self.cursor.fetchone()[0]
            # update the table "bind", insert if zero, update if bigger than zero
            if result == 0:
                self.cursor.execute(
                    'insert into bind(device_id, app_id, username, salted_hash_password, salt) values(%s, %s, %s, %s, %s)',
                    args=(device_id, bind_info[device_id]["app_id"], username_str, salted_hash_password, salt))
                self.connection.commit()
            else:
                self.cursor.execute(
                    'update bind set username=%s, salted_hash_password=%s, salt=%s where device_id=%s and app_id=%s',
                    args=(username_str, salted_hash_password, salt, device_id, bind_info[device_id]["app_id"]))
                self.connection.commit()

            # to device
            sent_data_to_device = compose_data(code=506, plain_data=app_id+klocal, enc_key=sockets[device_id].device_session["session_key"])
            self.bind506(device_id, sent_data_to_device)  # as sends success to device
            bind_info.pop(device_id)

            # to app
            return compose_data(code=507, plain_data=device_id+salt, enc_key=self.app_session["session_key"])

    def different702(self, rec_dict):
        if verify_message(rec_dict, hmac_key=self.app_session["session_key"]):
            decomposed_data = decompose_data(rec_dict, dec_key=self.app_session["session_key"])
            plain_data, = decomposed_data
            device_id = plain_data[:DEVICE_ID_BYTES]
            app_id = plain_data[DEVICE_ID_BYTES:DEVICE_ID_BYTES+APP_ID_BYTES]
            username_bytes = plain_data[DEVICE_ID_BYTES+APP_ID_BYTES:-HASH_SHA256_BYTES]
            username_str = str(username_bytes, encoding=MY_ENCODING)
            hash_password = plain_data[-HASH_SHA256_BYTES:]
            self.cursor.execute(
                'select salt, salted_hash_password from bind where device_id=%s and app_id=%s and username=%s',
                args=(device_id, app_id, username_str))
            salt, salted_hash_password = self.cursor.fetchone()
            db_salted_hash_password = my_hash(salt+hash_password)
            if db_salted_hash_password == salted_hash_password:
                if device_id in sockets:
                    rs_id = random_16bytes()
                    while rs_id in rs_ids:  # 防止重复的rs_id
                        rs_id = random_16bytes()
                    kdr = random_32bytes()
                    krp = random_32bytes()

                    sent_data_to_rs = compose_data(code=702, plain_data=device_id+app_id+rs_id+kdr+krp, enc_key=KRA)
                    to_rs_socket.transport.write(sent_data_to_rs)
                    sent_data_to_device = compose_data(code=703, plain_data=app_id+rs_id+kdr+RS_ADDR_BYTES, enc_key=sockets[device_id].device_session["session_key"])
                    sockets[device_id].transport.write(sent_data_to_device)
                    sent_data_to_app = compose_data(code=704, plain_data=device_id+rs_id+krp+RS_ADDR_BYTES, enc_key=self.app_session["session_key"])
                    return sent_data_to_app

    def update802(self, rec_dict):
        decomposed_data = decompose_data(rec_dict, dec_key=self.app_session["session_key"])
        plain_data, = decomposed_data
        device_id = plain_data[:DEVICE_ID_BYTES]
        app_id = plain_data[DEVICE_ID_BYTES:DEVICE_ID_BYTES+APP_ID_BYTES]
        r7 = plain_data[DEVICE_ID_BYTES+APP_ID_BYTES:DEVICE_ID_BYTES+APP_ID_BYTES+RANDOM_BYTES]
        mix_data = plain_data[DEVICE_ID_BYTES+APP_ID_BYTES+RANDOM_BYTES:]
        first_pos, second_pos = None, None
        for i in range(len(mix_data)):
            if mix_data[i].to_bytes(1, byteorder=BYTEORDER) == SPECIAL_BYTE:
                first_pos = i
                break
        for i in range(first_pos+HASH_SHA256_BYTES+1, len(mix_data)):
            if mix_data[i].to_bytes(1, byteorder=BYTEORDER) == SPECIAL_BYTE:
                second_pos = i
                break
        old_username_bytes = mix_data[:first_pos]
        old_hash_password = mix_data[first_pos+1:first_pos+1+HASH_SHA256_BYTES]
        new_username_bytes = mix_data[first_pos+1+HASH_SHA256_BYTES:second_pos]
        new_hash_password = mix_data[second_pos+1:]
        self.cursor.execute(
            'select salt, salted_hash_password from bind where device_id=%s and app_id=%s and username=%s',
            args=(device_id, app_id, old_username_bytes))
        salt, db_salted_hash_password = self.cursor.fetchone()
        salted_hash_password = my_hash(salt + old_hash_password)
        if db_salted_hash_password == salted_hash_password:
            sockets[app_id] = self
            if device_id in sockets:
                new_salt = create_salt()
                old_klocal = my_hash(device_id + app_id + old_username_bytes + salted_hash_password)
                new_klocal = my_hash(device_id + app_id + new_username_bytes + my_hash(new_salt + new_hash_password))
                update_info[app_id] = {
                    "random": r7,
                    "new_username": new_username_bytes,
                    "new_hash_password": new_hash_password,
                    "new_salt": new_salt,
                }
                plain_data = device_id + app_id + r7 + old_klocal + new_klocal
                sent_data_to_device = compose_data(code=802, plain_data=plain_data, enc_key=sockets[device_id].device_session["session_key"], hmac_key=sockets[device_id].device_session["session_key"])
                sockets[device_id].transport.write(sent_data_to_device)

    def update804(self, rec_dict):
        decomposed_data = decompose_data(rec_dict, dec_key=self.device_session["session_key"])
        plain_data, = decomposed_data
        app_id = plain_data[:APP_ID_BYTES]
        r7 = plain_data[APP_ID_BYTES:]
        if app_id in update_info.keys() and update_info[app_id]["random"] == r7:
            new_salted_hash_password = my_hash(update_info[app_id]["new_salt"]+update_info[app_id]["new_hash_password"])
            self.cursor.execute(
                'update bind set username=%s, salted_hash_password=%s, salt=%s where device_id=%s and app_id=%s',
                args=(update_info[app_id]["new_username"], new_salted_hash_password, update_info[app_id]["new_salt"],
                      self.device_session["device_id"], app_id))
            self.connection.commit()
            sent_data_to_app = compose_data(code=804, plain_data=r7+update_info[app_id]["new_salt"], enc_key=sockets[app_id].app_session["session_key"])
            sockets[app_id].transport.write(sent_data_to_app)

    def recover902(self, rec_dict):
        if verify_message(rec_dict, hmac_key=self.hmac_key):
            decomposed_data = decompose_data(rec_dict, dec_key=self.device_session["session_key"])
            plain_data, = decomposed_data
            device_id = plain_data[:DEVICE_ID_BYTES]
            r8 = plain_data[DEVICE_ID_BYTES:]
            if device_id == self.device_session["device_id"]:
                self.cursor.execute('delete from bind where device_id=%s', args=device_id)
                self.connection.commit()
                logger.info("has deleted all binding information in %s" % device_id)
                return compose_data(code=902, plain_data=r8, enc_key=self.device_session["session_key"])


class DefaultServerFactory(protocol.Factory):
    protocol = AuthServer


class ASClient(protocol.Protocol):
    def connectionMade(self):
        logger.info('connects with RS successfully')
        global to_rs_socket
        to_rs_socket = self

    def dataReceived(self, data):
        pass


class ASClientFactory(protocol.ClientFactory):
    protocol = ASClient
    clientConnectionLost = clientConnectionFailed = lambda self, connector, reason: \
        reactor.stop()


def main():
    reactor.connectTCP(RS_HOST, RS_PORT, ASClientFactory())  # AS runs its local tcp client to connect with RS
    logger.info("AS runs its local tcp client to connect with RS")
    reactor.listenTCP(AS_PORT, DefaultServerFactory())
    logger.info("the server hosted in AS is running")
    reactor.run()


if __name__ == '__main__':
    main()
