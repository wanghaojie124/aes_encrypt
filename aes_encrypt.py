# @require pycryptodome
# @time    2022-03-24
# @author  wanghj4@knowsec.com
import base64
from binascii import b2a_hex

from Crypto.Cipher import AES


class DeEnAesCrypt(object):
    """
    AES-128-CBC解密
    """
    AES_KEY = 'kcmap(3psc+u3+$f'
    AES_IV = 'c865674a838e71bd'

    def __init__(self, key=AES_KEY, iv=AES_IV, base=64, pad='zero'):
        """
        :param key: 随机的16位字符,加密使用的key
        :param pad: 填充方式
        """
        self.key = key
        self.iv = iv
        self.pad = pad
        self.base = base

    def decrypt_aes(self, text):
        """AES-128-CBC解密"""
        real_data = base64.b64decode(text)
        my_aes = AES.new(self.key.encode(), AES.MODE_CBC, iv=self.iv.encode())
        decrypt_data = my_aes.decrypt(real_data)
        return self.get_str(decrypt_data)

    @staticmethod
    def add_to_16(text):
        while len(text) % 16 != 0:
            text += '\0'.encode('utf-8')  # \0 可以被decode()自动清除，并且不会影响本来的字符0
        return text

    def encrypt_aes(self, text):
        """AES-128-CBC加密"""
        # 预处理,填充明文为16的倍数
        cryptor = AES.new(self.key.encode(), AES.MODE_CBC, iv=self.iv.encode())  # 此变量是一次性的(第二次调用值会变)不能作为常量通用
        ciphertext = cryptor.encrypt(self.add_to_16(text.encode('utf-8')))  # encode()转换是因为十六进制用的是字节码
        if self.base == 16:
            # 返回16进制密文
            return b2a_hex(ciphertext).decode('utf-8')
        elif self.base == 64:
            # 返回base64密文
            return base64.b64encode(ciphertext).decode('utf-8')

    def get_str(self, bd):
        """解密后的数据去除加密前添加的数据"""
        if self.pad == "zero":  # 去掉数据在转化前不足16位长度时添加的ASCII码为0编号的二进制字符
            return ''.join([chr(i) for i in bd if i != 0])
        elif self.pad == "pkcs7":  # 去掉pkcs7模式中添加后面的字符
            return ''.join([chr(i) for i in bd if i > 32])
        else:
            return "不存在此种数据填充方式"


if __name__ == '__main__':
    aes_er = DeEnAesCrypt()
    encrypt_text = aes_er.encrypt_aes("hello world")
    print(encrypt_text)
    decrypt_text = aes_er.decrypt_aes(encrypt_text)
    print(decrypt_text)
