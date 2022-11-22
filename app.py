#!/usr/bin/python3

from tinyec import registry
from tinyec.ec import SubGroup, Curve
import secrets, hashlib
from nummaster.basic import sqrtmod
from Crypto.Cipher import AES


# Krzywa używana w bitcoin.
# y^2 = x^3 + ax + b (mod p)
# p ~ rozmiar skończonego ciała (algebra) - dla bitcoin dosyć duże
# a i b - parametry samej krzywej, bitcoin 0 i 7
# n - rząd? krzywej, generalnie to liczba wszystkich punktów tej krzywej dla danego punktu G.
# h - związane z n, ale dla nas chyba nie istotne
# G - punkt generujący tą grupę n-punktów krzywej, trzeba odpowiednio razem z n dobrać. Mnożąc ten punkt przez liczbę całkowitą otrzymamy kolejny punkt z krzywej.
name = 'secp256k1'
p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
a = 0x0000000000000000000000000000000000000000000000000000000000000000
b = 0x0000000000000000000000000000000000000000000000000000000000000007
g = (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
     0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
h = 1
curve = Curve(a, b, SubGroup(p, g, n, h), name)
# curve = registry.get_curve('brainpoolP256r1')

# generowanie kluczy
# prywatny jest liczbą mniejszą od 'n' z powodu opisanego wyżej, mnożąc G przez kolejno 1...n otrzymamy unikalne? punkty, każda kolejna liczba da znowu te same punkty
# publiczny klucz to jest nowy punkt wygenerowany przez mnożenie punktu G przez klucz prywatny.
# To mnożenie nie jest takie normalne, opisane jest tutaj, biblioteka tinyec to implementuje, dlatego tu jest zwykłe mnożenie
# https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication
def generateKeys():
    privateKey = secrets.randbelow(curve.field.n)
    publicKey = privateKey * curve.g
    return (privateKey, publicKey)

# kompresja to taka sztuczka w sumie, krzywe eliptyczne są symetryczne względem osi X, wystarczy zapisać czy chodzi o punkt nad, albo pod 
def compressPoint(point):
    return (point[0], point[1] % 2)

def uncompressPoint(compressed_point, p, a, b):
    x, is_odd = compressed_point
    y = sqrtmod(pow(x, 3, p) + a * x + b, p)
    if bool(is_odd) == bool(y & 1):
        return (x, y)
    return (x, p - y)


# secret = (a * G) * b = (b * G) * a.
# cały diffie hellman to w sumie to działanie, oczywiście to mnożenie to jest to zdefiniowane dla tej krzywej, czyli nie takie zwykłe.
# a i b to klucze prywatne, przemnożenie przez G daje klucze publiczne, operacja mnożenia w tych krzywych jest przemienna/łączna chyba coś takiego, przez co obie strony otrzymają ten sam sekret
def difiHelman(publicKey, privateKey):
    return publicKey * privateKey


# Po difim helmanie mamy szyfrowanie symetryczne AES. 
def encryptAES(message, secretKey):
    aes = AES.new(secretKey, AES.MODE_GCM)
    encryptedMessage, authTag = aes.encrypt_and_digest(message)
    return (encryptedMessage, aes.nonce, authTag)

def decryptAES(encryptedMessage, nonce, authTag, secretKey):
    aes = AES.new(secretKey, AES.MODE_GCM, nonce)
    message = aes.decrypt_and_verify(encryptedMessage, authTag)
    return message

# Do AES trochę kiepsko wykorzystać punkt więc robi się z niego klucz 256-bitowy
def AES256KeyFromPoint(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()



def encryptECC(message, publicKey, privateKey):
    secretPoint = difiHelman(publicKey, privateKey)
    secretKey = AES256KeyFromPoint(secretPoint)

    encryptedMessage, nonce, authTag = encryptAES(message, secretKey)
    
    return encryptedMessage, nonce, authTag

def decryptECC(encryptedMessage, publicKey, privateKey, nonce, authTag):
    secretPoint = difiHelman(publicKey, privateKey)
    secretKey = AES256KeyFromPoint(secretPoint)

    return decryptAES(encryptedMessage, nonce, authTag, secretKey)


user1Private, user1Public = generateKeys()
user2Private, user2Public = generateKeys()

print("Klucze Usera 1")
print("Prywatny: ", user1Private)
print("Publiczny: ", user1Public)


print("Klucze Usera 2")
print("Prywatny: ", user2Private)
print("Publiczny: ", user2Public)

encryptedMessage, nonce, authTag = encryptECC(b'Ala ma kota', user2Public, user1Private)

print("======")
print("Zaszyfrowana wiadomość")
print(encryptedMessage)

decryptedMessage = decryptECC(encryptedMessage, user1Public, user2Private, nonce, authTag)

print("======")
print("Odszyfrowana wiadomość")
print(decryptedMessage)

