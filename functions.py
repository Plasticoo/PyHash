import hashlib
import base64
from lib import *

class CryptoLib:
    def __init__(self, word):
        self.word = word

    def CalculateBase64(self):
        return base64.b64encode(self.word)

    def CalculateBase64Salt(self, salt):
        return base64.b64encode(self.word + salt)

    def CalculateMD2(self):
        h = MD2.new()
        h.update(self.word)
        return h.hexdigest()

    def CalculateMD2Salt(self, salt):
        h = MD2.new()
        h.update(self.word + salt)
        return h.hexdigest()

    def CalculateMD4(self):
        return hashlib.new('md4', self.word.encode('utf-16le')).hexdigest()

    def CalculateMD4Salt(self, salt):
        return hashlib.new('md4', self.word.encode('utf-16le') + salt.encode('utf-16le')).hexdigest()

    def CalculateMD5(self):
        h = hashlib.md5()
        h.update(self.word)
        return h.hexdigest()

    def CalculateMD5Salt(self, salt):
        h = hashlib.md5()
        h.update(self.word + salt)
        return h.hexdigest()

    def CalculateSHA1(self):
        h = hashlib.sha1()
        h.update(self.word)
        return h.hexdigest()

    def CalculateSHA1Salt(self, salt):
        h = hashlib.sha1()
        h.update(self.word + salt)
        return h.hexdigest()

    def CalculateSHA224(self):
        h = hashlib.sha224()
        h.update(self.word)
        return h.hexdigest()

    def CalculateSHA224Salt(self, salt):
        h = hashlib.sha224()
        h.update(self.word + salt)
        return h.hexdigest()

    def CalculateSHA256(self):
        h = hashlib.sha256()
        h.update(self.word)
        return h.hexdigest()

    def CalculateSHA256Salt(self, salt):
        h = hashlib.sha256()
        h.update(self.word + salt)
        return h.hexdigest()

    def CalculateSHA384(self):
        h = hashlib.sha384()
        h.update(self.word)
        return h.hexdigest()

    def CalculateSHA384Salt(self, salt):
        h = hashlib.sha384()
        h.update(self.word + salt)
        return h.hexdigest()

    def CalculateSHA512(self):
        h = hashlib.sha512()
        h.update(self.word)
        return h.hexdigest()

    def CalculateSHA512Salt(self, salt):
        h = hashlib.sha512()
        h.update(self.word + salt)
        return h.hexdigest()

    def CalculateWhirlpool(self):
        h = whirlpool.new()
        h.update(self.word)
        return h.hexdigest()

    def CalculateWhirlpoolSalt(self, salt):
        h = whirlpool.new()
        h.update(self.word + salt)
        return h.hexdigest()

    def CalculateTiger(self):
        return tiger.hash(self.word).lower()

    def CalculateTigerSalt(self, salt):
        return tiger.hash(self.word + salt).lower()

    def CalculateMysql4(self):
        return oldmysql.mysql_hash_password(self.word)

    def CalculateMysql4Salt(self, salt):
        return oldmysql.mysql_hash_password(self.word + salt)

    def CalculateAllBasic(self):
        for i in hashlib.algorithms:
            h = hashlib.new(i)
            h.update(self.word)
            print i + ": " + h.hexdigest()

    def CalculateAllBasicSalt(self, salt):
        for i in hashlib.algorithms:
            h = hashlib.new(i)
            h.update(self.word + salt)
            print i + " " + h.hexdigest()

    def CalculateAllComplete(self):
        dictHash = {'Base64': self.CalculateBase64(),
                   'MD2': self.CalculateMD2(),
                   'MD4': self.CalculateMD4(),
                   'MD5': self.CalculateMD5(),
                   'SHA1': self.CalculateSHA1(),
                   'SHA224': self.CalculateSHA224(),
                   'SHA256': self.CalculateSHA256(),
                   'SHA384': self.CalculateSHA384(),
                   'SHA512': self.CalculateSHA512(),
                   'Whirlpool': self.CalculateWhirlpool(),
                   'Mysql4': self.CalculateMysql4(),
                   'Tiger': self.CalculateTiger()}

        sorted_list = [x for x in dictHash.iteritems()]
        sorted_list.sort(key=lambda x: x[0])

        for hash, value in sorted_list:
            print hash + ": " + value

    def CalculateAllCompleteSalt(self, salt):
        dictHash = {'Base64': self.CalculateBase64Salt(salt),
                   'MD2': self.CalculateMD2Salt(salt),
                   'MD4': self.CalculateMD4Salt(salt),
                   'MD5': self.CalculateMD5Salt(salt),
                   'SHA1': self.CalculateSHA1Salt(salt),
                   'SHA224': self.CalculateSHA224Salt(salt),
                   'SHA256': self.CalculateSHA256Salt(salt),
                   'SHA384': self.CalculateSHA384Salt(salt),
                   'SHA512': self.CalculateSHA512Salt(salt),
                   'Whirlpool': self.CalculateWhirlpoolSalt(salt),
                   'Mysql4': self.CalculateMysql4Salt(salt),
                   'Tiger': self.CalculateTigerSalt(salt)}

        sorted_list = [x for x in dictHash.iteritems()]
        sorted_list.sort(key=lambda x: x[0])

        for hash, value in sorted_list:
            print hash + ": " + value