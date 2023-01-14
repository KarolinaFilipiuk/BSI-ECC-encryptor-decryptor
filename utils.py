from Crypto.Cipher import AES
from base64 import b64encode, b64decode

def toBase64(bytes):
    return b64encode(bytes).decode('utf-8')

def fromBase64(data):
    return b64decode(data)
 
def encryptAES(data, key):
    aes = AES.new(key, AES.MODE_CFB)

    encrypted = aes.encrypt(data.encode("utf8"))
    initializationVector = aes.iv
    
    return toBase64(encrypted), toBase64(initializationVector)
    
def decryptAES(encrypted, key, initializationVector):
    aes = AES.new(key, AES.MODE_CFB, iv=fromBase64(initializationVector))
    
    data = aes.decrypt(fromBase64(encrypted))
    
    return data.decode("utf8")

def readForeignKey(path):
    file = open(path, "r")

    return file.read()
