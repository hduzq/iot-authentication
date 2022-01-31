from twisted.internet import protocol
from twisted.internet import reactor

from utils import *

RS_PORT = 9002  # the port of RS

APP_ID_BYTES = 8
TOKEN_BYTES = 16
PRODUCT_NAME_BYTES = 4
DEVICE_NAME_BYTES = 6
DEVICE_ID_BYTES = PRODUCT_NAME_BYTES + DEVICE_NAME_BYTES
RS_ID_BYTES = 16
KDR_BYTES = 32
KRP_BYTES = 32
DELTA_TIME = 3
LOOP_TIMES = 1

KRA = b'kra12345678901234567890123456789'

connection_info = {}  # the connection information stored in RS, key is rs_id, values contains device_id,app_id,kdr,krp
sockets = {}  # RS store the sockets of device and app, keys are device_id and app_id
logger.name = "AS"


class RSServer(protocol.Protocol):
    def __init__(self):
        self.switch = {
            702: self.different705,
            706: self.different708,
            707: self.different710,
            711: self.different712,
            713: self.different714
        }
        self.rs_id = None
        self.session_key = None
        self.hmac_key = None

    def connectionMade(self):
        logger.info("the address of the client is: {}".format(self.transport.getPeer()))

    def dataReceived(self, rec_data):
        code, rec_dict = analyze_rec_data(rec_data)
        sent_data = self.switch[code](rec_dict)
        if sent_data:
            self.transport.write(sent_data)
        return

    def different705(self, rec_dict):
        if verify_message(rec_dict, hmac_key=None):
            decomposed_data = decompose_data(rec_dict, dec_key=KRA)
            plain_data, = decomposed_data
            device_id = plain_data[:DEVICE_ID_BYTES]
            app_id = plain_data[DEVICE_ID_BYTES:DEVICE_ID_BYTES + APP_ID_BYTES]
            rs_id = plain_data[DEVICE_ID_BYTES + APP_ID_BYTES:DEVICE_ID_BYTES + APP_ID_BYTES + RS_ID_BYTES]
            kdr = plain_data[
                  DEVICE_ID_BYTES + APP_ID_BYTES + RS_ID_BYTES:DEVICE_ID_BYTES + APP_ID_BYTES + RS_ID_BYTES + KDR_BYTES]
            krp = plain_data[DEVICE_ID_BYTES + APP_ID_BYTES + RS_ID_BYTES + KDR_BYTES:]
            global connection_info
            connection_info[rs_id] = {
                "device_id": device_id,
                "app_id": app_id,
                "kdr": kdr,
                "krp": krp
            }

    def different708(self, rec_dict):
        rs_id = rec_dict[OTHER_DATA]
        self.rs_id = rs_id
        if rs_id in connection_info.keys() and verify_message(rec_dict, hmac_key=connection_info[rs_id]["kdr"]):
            sockets[connection_info[rs_id]["device_id"]] = self
            self.session_key = connection_info[rs_id]["kdr"]
            self.hmac_key = self.session_key
            sent_data = compose_data(code=708, plain_data=b'different ok', enc_key=connection_info[rs_id]["kdr"])
            return sent_data

    def different710(self, rec_dict):
        rs_id = rec_dict[OTHER_DATA]
        self.rs_id = rs_id
        if rs_id in connection_info.keys() and verify_message(rec_dict, hmac_key=connection_info[rs_id]["krp"]):
            sockets[connection_info[rs_id]["app_id"]] = self
            self.session_key = connection_info[rs_id]["krp"]
            self.hmac_key = self.session_key
            sent_data = compose_data(code=710, plain_data=b'different ok', enc_key=connection_info[rs_id]["krp"])
            return sent_data

    def different712(self, rec_dict):
        if verify_message(rec_dict, hmac_key=self.hmac_key):
            decomposed_data = decompose_data(rec_dict, dec_key=self.session_key)
            plain_data, = decomposed_data
            message = plain_data
            logger.info("收到业务消息{message}".format(message=message))

            device_id = connection_info[self.rs_id]["device_id"]
            sent_data_to_device = compose_data(code=712, plain_data=message, enc_key=connection_info[self.rs_id]["kdr"],
                                               hmac_key=connection_info[self.rs_id]["kdr"])
            sockets[device_id].transport.write(sent_data_to_device)

    def different714(self, rec_dict):
        if verify_message(rec_dict, hmac_key=self.hmac_key):
            decomposed_data = decompose_data(rec_dict, dec_key=self.session_key)
            plain_data, = decomposed_data
            message = plain_data
            logger.info("收到业务消息{message}".format(message=message))

            app_id = connection_info[self.rs_id]["app_id"]
            sent_data_to_app = compose_data(code=714, plain_data=message, enc_key=connection_info[self.rs_id]["krp"],
                                            hmac_key=connection_info[self.rs_id]["krp"])
            sockets[app_id].transport.write(sent_data_to_app)


class RSServerFactory(protocol.Factory):
    protocol = RSServer


def main():
    reactor.listenTCP(RS_PORT, RSServerFactory())
    logger.info('RS is running')
    reactor.run()


if __name__ == '__main__':
    main()
