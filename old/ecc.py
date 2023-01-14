#!/usr/bin/python3
# main.py
import sys
import argparse
from app import *
from getpass import getpass
import hashlib

def getPassword():
    return getpass("Enter passphrase: ")

def hashPassword(password):
    return hashlib.sha256(password.encode("utf-8")).digest()

def savePrivateKeyFile(encryptedPrivateKey, nonce, authTag):
    file = open("privateKey", "wb")
    file.write(encryptedPrivateKey)
    file.write(nonce)
    file.write(authTag)
    file.close()

def readPrivateKeyFromFile():
    file = open("privateKey", "rb")
    privateKey = file.read(77)
    print(len(privateKey))
    nonce = file.read(16)
    print(len(nonce))
    authTag = file.read(16)
    print(len(authTag))
    file.close()
    return privateKey, nonce, authTag

def onGenerate():
    password = hashPassword(getPassword())
    privateKey, publicKey = generateKeys()
    encryptedPrivateKey, nonce, authTag = encryptAES(str(privateKey).encode("utf8"), password)
    print(f"{password}, {len(encryptedPrivateKey)}, {len(nonce)}, {len(authTag)}") # 77 16 16
    savePrivateKeyFile(encryptedPrivateKey, nonce, authTag)
    savePublicKeyFile(publicKey)

def savePublicKeyFile(publicKey):
    key, sign = compressPoint(publicKey)
    file = open("publicKey", "w")
    file.write(f"{key},{sign}")
    file.close()

def saveForeignPublicKey(key, name):
    file = open("foreignPublicKeys", "a")
    file.write(f"{name} : {key}\n")
    file.close()

def onAddKey():
    key = input("Enter foreign public key: ")
    keyName = input("Enter key name: ")
    saveForeignPublicKey(key, keyName)

def onListKeys():
    with open("foreignPublicKeys", 'r') as file:
        print(file.read())
    file.close()

def readForeignPublicKeyFromFile(keyName):
    file = open('foreignPublicKeys', 'r')
    lines = file.readlines()
    foreignPublicKey = ""
    for line in lines:
        if line.startswith(keyName):
            foreignPublicKey = line.split(sep=':')[1].strip()
    file.close()
    if foreignPublicKey == "":
        raise RuntimeError('Key not found') # proforma, do poprawy
    return foreignPublicKey

def onEncrypt():
    message = input("Enter message to encrypt: ")
    foreignPublicKeyName = input("Enter foreign public key name: ")
    foreignPublicKey = readForeignPublicKeyFromFile(foreignPublicKeyName)
    password = hashPassword(getPassword())
    encryptedPrivateKey, nonce, authTag = readPrivateKeyFromFile()
    privateKey = decryptAES(encryptedPrivateKey, nonce, authTag, password)
    encryptedMessage, nonce, authTag = encryptECC(message.encode("utf8"), foreignPublicKey, privateKey) # co z tym zrobić? zapisać do pliku?
    print(encryptedMessage)
    print(nonce)
    print(authTag)

if __name__ == "__main__":
    # Create the parser
    parser = argparse.ArgumentParser(description="dawdawd")
    # Add an argument
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--generate', action='store_true')
    group.add_argument('--encrypt', action='store_true')
    group.add_argument('--decrypt', action='store_true')
    group.add_argument('--addKey', action='store_true')
    group.add_argument('--listKeys', action='store_true')
    # Parse the argument
    args = parser.parse_args()

    if args.generate:
        onGenerate()

    elif args.encrypt:
        onEncrypt()

    elif args.decrypt:
        pass

    elif args.addKey:
        onAddKey()

    elif args.listKeys:
        onListKeys()

