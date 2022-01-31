import configparser
import hmac
import time
from hashlib import sha256
import random

import pymysql
from Crypto import Random
from Crypto.Cipher import AES

from constants import *


def random_16bytes():
    return Random.new().read(16)


def random_32bytes():
    return Random.new().read(32)


def my_hash(data):
    """
    :param data: bytes
    :return: bytes
    """
    return sha256(data).digest()


def pkcs7_padding(text):
    """
    The plaintext is padded using PKCS7
    When you finally call the AES encryption method, you pass in a byte array that
    is required to be multiple integers of 16, so you need to process the plaintext
    :param text: bytes
    :return: padded_bytes
    """
    bs = AES.block_size  # 16
    length = len(text)
    padding = bs - length % bs
    padding_text = padding.to_bytes(1, byteorder=BYTEORDER) * padding
    return text + padding_text


def pkcs7_unpadding(text):
    """
    Process data that has been padded with PKCS7
    :param text: The decrypted bytes
    :return: bytes
    """
    length = len(text)
    unpadding = text[length - 1]
    return text[0:length - unpadding]


def aes_enc(key, data):
    """
    AES encryption
    IV, 16 bytes, randomly generated
    mode: CBC
    padded by pkcs7
    :param key: bytes
    :param data: bytes
    :return: iv_cipher
    """
    iv = random_16bytes()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pkcs7_padding(data)
    encoded_data = cipher.encrypt(padded_data)
    iv_cipher = iv + encoded_data
    return iv_cipher


def aes_dec(key, iv_cipher):
    """
    AES decryption
     iv obtained from the first 16bytes of the ciphertext
    mode: CBC
    padded by pkcs7
    :param key: bytes
    :param iv_cipher
    :return: data
    """
    iv = iv_cipher[:16]
    encoded_data = iv_cipher[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decoded_bytes = cipher.decrypt(encoded_data)
    data = pkcs7_unpadding(decoded_bytes)
    return data


def my_hmac(key, data):
    """
    Use sha256 for HMAC calculations
    :param key: bytes
    :param data: bytes
    :return: hmac(bytes)
    """
    # 处理明文
    padded_data = pkcs7_padding(data)
    digest = hmac.new(key, padded_data, digestmod=HASH_FUNCTION).digest()
    return digest


def create_salt(salt_len=16):
    salt = bytearray()
    chars = b'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz0123456789'
    for i in range(salt_len):
        salt.append(chars[random.randint(0, len(chars) - 1)])
    return bytes(salt)


def init_conf():
    config = configparser.ConfigParser()
    config.read("device2.conf")
    return config


if __name__ == '__main__':
    data = b'12345678901234567890123456789012'
    key = b'kbind123456789012345678901234567'
    key_16 = b'1234567890123456'

    # cipher = aes_enc(key_16, data)

    connection = pymysql.connect(
        host="localhost",
        user='root',
        password='123456',
        database='as',
        charset='utf8'
    )
    cursor = connection.cursor()

    start_time = time.time_ns()
    config = init_conf()
    for i in range(1):
        # cursor.execute("select product_secret from product where product_name=%s", args="prod")
        # cursor.execute('insert into app(app_id) values(%s)', args=b'iamappkk')
        # cursor.execute('delete from app where app_id=%s', args=b'iamappkk')
        # connection.commit()
        # my_hash(data)
        # aes_enc(key, data)
        # aes_dec(key, cipher)
        # digest = my_hmac(key, data)
        config.set('device', 'device_secret', "kbind123456789012345678901234567")
        config.write(open("device2.conf", "w"))
        # config.remove_option('device', 'device_secret')
        # config.write(open("device2.conf", "w"))
    end_time = time.time_ns()
    print(end_time - start_time)
