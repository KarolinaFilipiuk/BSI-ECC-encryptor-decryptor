from utils import encryptAES, decryptAES
from nummaster.basic import sqrtmod
import tinyec.ec as ec
import hashlib, secrets

name = 'secp256k1'
p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
a = 0x0000000000000000000000000000000000000000000000000000000000000000
b = 0x0000000000000000000000000000000000000000000000000000000000000007
g = (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
     0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
h = 1
curve = ec.Curve(a, b, ec.SubGroup(p, g, n, h), name)


def generateKeys():
    privateKey = secrets.randbelow(curve.field.n)
    publicKey = privateKey * curve.g
    return (privateKey, publicKey)

def compressPoint(point):
    return (point.x, point.y % 2)

def uncompressPoint(compressedPoint):
    x, isOdd = compressedPoint.split(",")

    x = int(x)
    isOdd = int(isOdd)

    y = sqrtmod(pow(x, 3, p) + a * x + b, p)
    if bool(isOdd) == bool(y & 1):
        return (x, y)
    return ec.Point(curve, x, p - y)

def difiHelman(publicKey, privateKey):
    return publicKey * privateKey

def AES256KeyFromPoint(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

def encryptECC(message, publicKey, privateKey):
    secretPoint = difiHelman(publicKey, privateKey)
    secretKey = AES256KeyFromPoint(secretPoint)

    encryptedMessage, initializationVector = encryptAES(message, secretKey)
    
    return encryptedMessage, initializationVector

def decryptECC(encryptedMessage, publicKey, privateKey, initializationVector):
    secretPoint = difiHelman(publicKey, privateKey)
    secretKey = AES256KeyFromPoint(secretPoint)

    return decryptAES(encryptedMessage, secretKey, initializationVector)
