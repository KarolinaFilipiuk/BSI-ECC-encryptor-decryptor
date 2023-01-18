#!/usr/bin/python3
import argparse

from keys import onGenerate, onAddKey, onListKeys
from encryption import onDecrypt, onEncrypt

parser = argparse.ArgumentParser()

commandParser = parser.add_subparsers(dest="command")

generateParser = commandParser.add_parser("generate")

generateParser.add_argument("--path", type=str)

addKeysParser = commandParser.add_parser("addKey")

addKeysParser.add_argument("--path", type=str)
addKeysParser.add_argument("--key", type=str)
addKeysParser.add_argument("--name", type=str)

listKeysParser = commandParser.add_parser("listKeys")

encryptParser = commandParser.add_parser("encrypt")

encryptParser.add_argument("--path", type=str)
encryptParser.add_argument("--key", type=str)
encryptParser.add_argument("--name", type=str)


decryptParser = commandParser.add_parser("decrypt")

decryptParser.add_argument("--path", type=str)

args = parser.parse_args()

match args.command:
    case "generate":
        onGenerate(args.path)

    case "addKey":
        onAddKey(args.path, args.key, args.name)

    case "listKeys":
        onListKeys()

    case "encrypt":
        onEncrypt(args.path, args.key, args.name)
        
    case "decrypt":
        onDecrypt(args.path)

        
