import json
import pickle
import time
import logging
from logging import handlers
import datetime

from mycrypto import *


class DateEncoder(json.JSONEncoder):
    """
    将python中的时间类型转为为字符串，以便存入json
    """

    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        elif isinstance(obj, datetime.date):
            return obj.strftime("%Y-%m-%d")
        else:
            return json.JSONEncoder.default(self, obj)


class Logger(object):
    """
    日志工具类
    """
    level_relations = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
        'critical': logging.CRITICAL
    }  # 日志级别关系映射

    def __init__(self, filename, level='info', when='D', backCount=3,
                 fmt='%(asctime)s %(levelname)s %(name)s %(funcName)s [line:%(lineno)d]: %(message)s'):
        # self.logger = logging.getLogger(filename)
        self.logger = logging.getLogger(__name__)
        format_str = logging.Formatter(fmt)  # 设置日志格式
        self.logger.setLevel(self.level_relations.get(level))  # 设置日志级别
        sh = logging.StreamHandler()  # 往屏幕上输出
        sh.setFormatter(format_str)  # 设置屏幕上显示的格式
        th = handlers.TimedRotatingFileHandler(filename=filename, when=when, backupCount=backCount,
                                               encoding='utf-8')  # 往文件里写入#指定间隔时间自动生成文件的处理器
        # 实例化TimedRotatingFileHandler
        # interval是时间间隔，backupCount是备份文件的个数，如果超过这个个数，就会自动删除，when是间隔的时间单位，单位有以下几种：
        # S 秒
        # M 分
        # H 小时、
        # D 天、
        # W 每星期（interval==0时代表星期一）
        # midnight 每天凌晨
        th.setFormatter(format_str)  # 设置文件里写入的格式
        self.logger.addHandler(sh)  # 把对象加到logger里
        self.logger.addHandler(th)


logger = Logger('logs/iot_authentication.log', level='debug').logger


def store_json(content, json_file):
    """
    存储字典为json文件
    :param content: 传入字典
    :param json_file: json文件
    :return:
    """
    with open(json_file, 'w') as file:
        # file.write(json.dumps(result, indent=4, cls=DateEncoder))
        json.dump(content, file, indent=4, cls=DateEncoder)
    logger.info("store {file} successfully.".format(file=json_file))


def load_json(json_file, key=None):
    """
    从json文件读取字典
    :param json_file: json文件
    :param key: 指定键读取
    :return: 读取的字典
    """
    with open(json_file, 'r', encoding='utf8')as file:
        if key is None:
            return json.load(file)
        else:
            return json.load(file)[key]


def calc_method_time(func):
    """
    计算方法所耗时间
    :param func: 方法
    :return: 耗时
    """

    def inner(*args, **kwargs):
        logger.info("开始运行方法: %s" % func.__name__)
        start = time.time()
        res = func(*args, **kwargs)
        end = time.time()
        logger.info("运行方法: %s完毕, 运行共计耗时: %s s" % (func.__name__, end - start))
        return res

    return inner


def compose_data(code, other_data=None, plain_data=None, enc_key=None, hmac_key=None):
    sent_dict = {
        CODE: code
    }
    data = b''
    if code in CODES_WITH_TIME:
        timestamp = int(time.time())
        data += timestamp.to_bytes(TIMESTAMP_BYTES, byteorder=BYTEORDER)
        sent_dict.update({TIMESTAMP: timestamp})
    if code in CODES_WITH_OTHER:
        data += other_data
        sent_dict.update({OTHER_DATA: other_data})
    if code in CODES_WITH_ENCRYPT:
        encrypted_data = aes_enc(enc_key, plain_data)
        data += encrypted_data
        sent_dict.update({ENCRYPTED_DATA: encrypted_data})
    if code in CODES_WITH_HMAC:
        hmac_data = my_hmac(hmac_key, data)
        sent_dict.update({HMAC_DATA: hmac_data})
    sent_data = pickle.dumps(sent_dict)
    logger.info("发送长度为{length}的消息:{sent_dict}".format(length=len(sent_data), sent_dict=sent_dict))
    return sent_data


def analyze_rec_data(rec_data):
    rec_dict = pickle.loads(rec_data)
    code = rec_dict[CODE]
    logger.info("对{code}消息的解析结果:{rec_dict}".format(code=code, rec_dict=rec_dict))
    return code, rec_dict


def verify_message(rec_dict, hmac_key=None):
    data = b''
    code = rec_dict[CODE]
    # 检验时间戳
    if code in CODES_WITH_TIME:
        timestamp = rec_dict[TIMESTAMP]
        if int(time.time()) - timestamp >= 3:
            raise Exception("在{code}中时间差超过设定值3s".format(code=code))
        data += timestamp.to_bytes(TIMESTAMP_BYTES, byteorder=BYTEORDER)
    if code in CODES_WITH_OTHER:
        other_data = rec_dict[OTHER_DATA]
        data += other_data
    if code in CODES_WITH_ENCRYPT:
        encrypted_data = rec_dict[ENCRYPTED_DATA]
        data += encrypted_data
    if code in CODES_WITH_HMAC:
        if my_hmac(hmac_key, data) != rec_dict[HMAC_DATA]:
            raise Exception("在{code}中HMAC检验错误".format(code=code))
    logger.info("检验{code}成功".format(code=code))
    return True


def decompose_data(rec_dict, dec_key=None):
    code = rec_dict[CODE]
    decomposed_data = list()
    if code in CODES_WITH_OTHER:
        other_data = rec_dict[OTHER_DATA]
        decomposed_data.append(other_data)
    if code in CODES_WITH_ENCRYPT:
        encrypted_data = rec_dict[ENCRYPTED_DATA]
        decrypted_data = aes_dec(dec_key, encrypted_data)
        decomposed_data.append(decrypted_data)
    logger.info("从{code}中分解出消息:{decomposed_data}".format(code=code, decomposed_data=decomposed_data))
    return decomposed_data


def save_dict(my_dict, filename):
    # np.save(filename, my_dict)
    with open(filename, 'wb') as f:
        pickle.dump(my_dict, f, pickle.HIGHEST_PROTOCOL)


def load_dict(filename):
    # return np.load(filename).item()
    with open(filename, 'rb') as f:
        return pickle.load(f)


def get_addr_bytes(ip_str, port):
    ip_byte_list = [int(ip_part).to_bytes(1, byteorder=BYTEORDER) for ip_part in ip_str.split(".")]
    ip_bytes = b''.join(ip_byte_list)
    port_bytes = port.to_bytes(PORT_BYTES, byteorder=BYTEORDER)
    return ip_bytes + port_bytes


def get_addr_str_int(addr_bytes):
    ip_bytes = addr_bytes[:IP_BYTES]
    port_bytes = addr_bytes[IP_BYTES:]
    ip_char_list = [str(ip_byte) for ip_byte in ip_bytes]
    ip_str = '.'.join(ip_char_list)
    port = int.from_bytes(port_bytes, byteorder=BYTEORDER)
    return ip_str, port


if __name__ == '__main__':
    my_dict = {"a": b'1'}
    # my_bytes = pickle.dumps(my_dict)
    # print(my_bytes)
    # new_dict = pickle.loads(my_bytes)
    # print(new_dict)
    # save_dict(my_dict, filename)
    # print(load_dict(filename))

    # ip_str = "192.168.1.100"
    # port = 1234
    # addr_bytes = get_addr_bytes(ip_str, port)
    # print(addr_bytes)
    # ip_str, port = get_addr_str_int(addr_bytes)
    # print(ip_str)
    # print(port)
    pass
