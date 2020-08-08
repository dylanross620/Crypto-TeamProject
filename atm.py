import json
import hash
import socket
import select
from PublicKey import rsa
from PublicKey import elgamal
from PrivateKey import aes
import time
class ATM:
    def __init__(self, username, password, preflist = []):
        self.user = username
        self.pw  = hash.sha256(password)
        self.aeskey = aes.generate_key()
        # self.aeskey = str(secrets.token_bytes(32)) #32 bytes = 256 bits for AES
        # print("atm aes secret len: " + str(len(self.aeskey))) #testing ---------- delete later
        # print("atm aes secret: " + self.aeskey) #testing ---------- delete later
        if len(preflist) == 0:
            raise Exception("need to have preferences as the user to compare to server...")
        self.prefs = preflist
        self.scheme = None
        self.pubkey = None
        self.privkey = None
        self.bankpubkey = None
        self.s = socket.socket()
        self.s.connect(('127.0.0.1', 5432))
        # self.s.settimeout(1)

    def withdraw_money(self):
        pass

    def deposit_money(self):
        pass

    def starthandshake(self):
        # self.s.send()
        # msg = self.s.recv(1024)
        # print(msg)
        # self.s.close()
        self.s.send((self.user + '-' + str(self.prefs)).encode('utf-8'))
        bankhello = self.s.recv(1024)

        bankhello = bankhello.decode('utf-8').split('-')
        self.scheme = bankhello[0]
        self.bankpubkey = eval(bankhello[1])
        print(self.bankpubkey)
        
        return True


    def key_setup(self, bpubkey):
        if self.scheme == None:
            raise Exception("need to assign common scheme in atm!")
        keypairs = None
        if self.scheme == "rsa":
            keypairs = rsa.load_keys("local_storage/atm-rsa.txt", 4096)
        else:
            keypairs = elgamal.load_keys("local_storage/atm-elgamal.txt",4096)
        self.pubkey = keypairs[0]
        self.privkey = keypairs[1]
        self.bankpubkey = bpubkey
        ekey = None
        if self.scheme == "rsa":
            ekey = rsa.encrypt(self.aeskey + hash.sha256(self.aeskey),self.bankpubkey)
        else:
            ekey = elgamal.encrypt(self.aeskey + hash.sha256(self.aeskey), self.bankpubkey)

        return ekey #this is being sent across the network, could intercept here before bank recieves...

    def send_user(): #need to hash, append to hash end of message, encrypt all, then send and check validity of hash in bank.py
        pass
    
    def send_pass(): #need to hash, append to hash end of message, encrypt all, then send and check validity of hash in bank.py
        pass

if __name__ == "__main__":
    atmtest = ATM("Alex","alexpassword",["rsa"])
    atmtest2 = ATM("Owen","owenpassword",["elgamal"])