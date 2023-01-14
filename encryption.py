from keys import readForeignPublicKeys, printForeignKeys, getPrivateKey
from eccs import uncompressPoint, encryptECC, decryptECC
from utils import readForeignKey

def onEncrypt(path, key, name):
    message = input("Enter message to encrypt: ")

    if not key: 
        keys = readForeignPublicKeys()

        result = [keyInfo for keyInfo in keys if keyInfo[0] == name] if name else None

        while not result:
            name = input("Enter recipient public key name(type L to show list of saved ones): ").strip()

            if name == "L":
                printForeignKeys(keys)
                print("")
                continue

            result = [keyInfo for keyInfo in keys if keyInfo[0] == name.strip()]

        key = f"{result[0][1]},{result[0][2]}"

    uncompressedKey = uncompressPoint(key)

    path = input("Enter folder containing private key(./): ")
    if not path: path = "./"
    
    privateKey = getPrivateKey(path.strip())

    publicKey = readForeignKey(f"{path.strip().rstrip('/')}/publicKey")
        
    encryptedMessage, initializationVector = encryptECC(message, uncompressedKey, privateKey)

    print(f"Your message: {encryptedMessage}.{initializationVector}.{publicKey}")

    
def onDecrypt(path):
    message = input("Enter message to decrypt: ")
    
    encryptedMessage, initializationVector, publicKey = message.split(".")

    keys = readForeignPublicKeys()

    key, sign = publicKey.split(",")

    found = [keyInfo for keyInfo in keys if keyInfo[1] == key and keyInfo[2] == sign]

    if(found):
        print(f"Message from {found[0]}")
    else:
        print(f"Sender of a message is unknown")
        add = input("Add sender to known keys? [y/N]: ")
        if add == "Y" or add == "y":
            name = input("Enter name of sender: ")
            if not name:
                print("Name inccorect")
                exit(-1)
            saveForeignPublicKey(publicKey, name.strip())
    
    uncompressedKey = uncompressPoint(publicKey)

    path = input("Enter folder containing private key(./): ")
    if not path: path = "./"
    
    privateKey = getPrivateKey(path.strip())

    try:
        decrypted = decryptECC(encryptedMessage, uncompressedKey, privateKey, initializationVector)
    except:
        print("Cannot decrypt message")
        return
    
        
    print(f"Your message: {decrypted}")
