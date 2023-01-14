import hashlib
from getpass import getpass

from utils import encryptAES, decryptAES, readForeignKey
from eccs import generateKeys, compressPoint 

def getPassword():
    password =  getpass("Enter passphrase: ")

    while not password:
        password = getpass("Plese enter passphrase: ")

    return password

def hashPassword(password):
    return hashlib.sha256(password.encode("utf-8")).digest()

def savePrivateKey(path, encryptedPrivate, initializationVector):
    file = open(f"{path}/privateKey", "w")

    file.write(f"{initializationVector}\n{encryptedPrivate}")
    file.close()
    
def savePublicKey(path, publicKey):
    key, sign = compressPoint(publicKey)
        
    file = open(f"{path}/publicKey", "w")

    file.write(f"{key},{sign}")
    file.close()

def readPrivateKey(path):
    file = open(f"{path}/privateKey", "r")

    initializationVector, privateKey = file.readlines()
    
    return privateKey.strip(), initializationVector.strip()

def getPrivateKey(path):
    encryptedKey, initializationVector = readPrivateKey(path)
    password = hashPassword(getPassword())

    privateKey = 0
    
    try:
        privateKey = int(decryptAES(encryptedKey, password, initializationVector))
    except:
        print("Incorrect password")
        exit(-1)

    return privateKey  
    
    
def saveForeignPublicKey(key, name):
    file = open("keyRing", "a")
    file.write(f"{name}: {key}\n")
    file.close()

def readForeignPublicKeys():
    try:
        file = open('keyRing', 'r')
    except:
        print("No saved keys")
        exit(-1)
    
    lines = file.readlines()

    keys = []

    for line in lines:
        name, rest = line.strip().split(":")
        key, sign = rest.split(",")
        keys.append([name, key.strip(), sign])
        
    return keys

def printForeignKeys(keys):
    for name, key, sign in keys:
        print(f"{name}: <{key},{sign}>")
	       
def onGenerate(path):
    if not path:
        path = input("Enter path in which to save the key (./): ")
        if not path: path = "./"

    path = path.strip().rstrip("/")
    
    password = hashPassword(getPassword())
    privateKey, publicKey = generateKeys()

    encryptedPrivate, initializationVector = encryptAES(str(privateKey), password)

    savePrivateKey(path, encryptedPrivate, initializationVector)
    savePublicKey(path, publicKey)

    
def onAddKey(path, key, name):
    if(path):
        key = readForeignKey(path)

    if not key:
        key = input("Enter foreign public key: ")

    if not key or not "," in key:
        try:
            key = readForeignKey(key)
        except:
            print("Maflormed key")
            return
        
    
    if not name:
        name = input("Enter key name: ")

    if not name:
        print("Name inccorect")
        return

    saveForeignPublicKey(key, name.strip())

def onListKeys():
    keys = readForeignPublicKeys()

    printForeignKeys(keys)
