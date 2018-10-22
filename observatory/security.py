# -*- coding: utf-8 -*-

import base64
import random
import socket
import string
import struct

from Crypto.Cipher import AES


class PKCS7Encoder(object):
  """提供基于PKCS7算法的加解密接口"""

  def __init__(self):
    self.block_size = 32

  def encode(self, text):
    """ 对需要加密的明文进行填充补位
    @param text: 需要进行填充补位操作的明文
    @return: 补齐明文字符串
    """
    text_length = len(text)
    # 计算需要填充的位数
    amount_to_pad = self.block_size - (text_length % self.block_size)
    if amount_to_pad == 0:
      amount_to_pad = self.block_size
    # 获得补位所用的字符
    pad = chr(amount_to_pad).encode('utf8')
    return text + pad * amount_to_pad

  def decode(self, decrypted):
    """
    删除解密后明文的补位字符
    @param decrypted: 解密后的明文
    @return: 删除补位字符后的明文
    """
    pad = ord(decrypted[-1])
    if pad < 1 or pad > 32:
      pad = 0
    return decrypted[:-pad]


class Prpcrypt(object):
  """提供接收和推送给公众平台消息的加解密接口"""

  def __init__(self, key):
    self.key = base64.b64decode(key + "=")
    self.mode = AES.MODE_CBC

  def encrypt(self, text, appid):
    """
    对明文进行加密
    @param text: 需要加密的明文
    @param appid: AppID
    @return: 加密得到的字符串
    """
    # 16位随机字符串添加到明文开头
    text = text.encode('utf8')
    appid = appid.encode('utf8')
    rand_str = "".join(
        random.sample(string.ascii_letters + string.digits, 16)).encode(
        'utf8')
    text = rand_str + struct.pack("I", socket.htonl(
        len(text))) + text + appid
    # 使用自定义的填充方式对明文进行补位填充
    pkcs7 = PKCS7Encoder()
    text = pkcs7.encode(text)
    # 加密
    cryptor = AES.new(self.key, self.mode, self.key[:16])
    ciphertext = cryptor.encrypt(text)
    # 使用BASE64对加密后的字符串进行编码
    return base64.b64encode(ciphertext).decode('utf8')

  def decrypt(self, ciphertext, appid):
    """
    对解密后的明文进行补位删除
    @param ciphertext: 密文
    @param appid: AppID
    @return: 删除填充补位后的明文
    """
    cryptor = AES.new(self.key, self.mode, self.key[:16])
    # 使用BASE64对密文进行解码，然后AES-CBC解密
    text = cryptor.decrypt(base64.b64decode(ciphertext))

    pad = text[-1]
    # 去除16位随机字符串
    content = text[16:-pad]
    text_len = socket.ntohl(struct.unpack("I", content[:4])[0])
    text = content[4: 4 + text_len].decode('utf8')
    from_appid = content[4 + text_len:].decode('utf8')
    if from_appid != appid:
      raise ValueError('Unmatched AppID')
    return text
