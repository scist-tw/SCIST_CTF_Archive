#!/usr/bin/env python3
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad

KEY = os.urandom(16)
IV = os.urandom(16)
FLAG = open('./flag', 'rb').read()

def main():
    aes = AES.new(KEY, AES.MODE_CFB, IV)
    cipher = aes.encrypt(pad(FLAG, 16, 'pkcs7'))
    print(f'flag = {(IV + cipher).hex()}')

    while True:
        cipher = bytes.fromhex(input('cipher = ').strip())
        iv, cipher = cipher[:16], cipher[16:]
        try:
            aes = AES.new(KEY, AES.MODE_CFB, iv)
            plain = unpad(aes.decrypt(cipher), 16, 'pkcs7')
            print('Correct')
        except ValueError:
            print('Error')

main()
