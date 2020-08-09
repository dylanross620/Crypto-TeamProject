import json
import hash
import socket
import ast
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

    def withdraw_money(self):
        pass

    def deposit_money(self):
        pass

    def starthandshake(self):
        self.s.send((self.user + '-' + str(json.dumps(self.prefs))).encode('utf-8'))
        bankhello = self.s.recv(4096)
        self.scheme = bankhello.decode('utf-8')
        if self.scheme == "rsa":
            keypairs = rsa.load_keys("local_storage/atm-rsa.txt", 4096)
            bkeypairs = rsa.load_keys("local_storage/bank-rsa.txt",4096)
            self.bankpubkey = bkeypairs[0] # simulates the bank's public keys being hardcoded into the atm. This way if we chose to reset the bank key, we don't have to update this
        else:
            keypairs = elgamal.load_keys("local_storage/atm-elgamal.txt",2048)
            bkeypairs = elgamal.load_keys("local_storage/bank-elgamal.txt",2048)
            self.bankpubkey = bkeypairs[0] # see above
        self.pubkey = keypairs[0]
        self.privkey = keypairs[1]
        print("Handshake info --> sending over atm pubkey...")
        pubkeystr = str(self.pubkey)
        pkeylen = len(pubkeystr) // 4
        print(pkeylen)
        q1 = pubkeystr[0:pkeylen]
        q2 = pubkeystr[pkeylen:(pkeylen*2)]
        q3 = pubkeystr[(pkeylen*2):(pkeylen*3)]
        q4 = pubkeystr[(pkeylen*3):]
        q1 = q1 + '-' + hash.sha256(q1)
        q2 = q2 + '-' + hash.sha256(q2)
        q3 = q3 + '-' + hash.sha256(q3)
        q4 = q4 + '-' + hash.sha256(q4)
        if self.scheme == 'rsa':
            q1 = rsa.encrypt(q1,self.bankpubkey)
            q2 = rsa.encrypt(q2,self.bankpubkey)
            q3 = rsa.encrypt(q3,self.bankpubkey)
            q4 = rsa.encrypt(q4,self.bankpubkey)
        else:
            q1 = elgamal.encrypt(q1,self.bankpubkey)
            q2 = elgamal.encrypt(q2,self.bankpubkey)
            q3 = elgamal.encrypt(q3,self.bankpubkey)
            q4 = elgamal.encrypt(q4,self.bankpubkey)
        self.s.send(str(q1).encode('utf-8'))
        print(f"Handshake info --> bank replied {self.s.recv(1024).decode('utf-8')}")
        self.s.send(str(q2).encode('utf-8'))
        print(f"Handshake info --> bank replied {self.s.recv(1024).decode('utf-8')}")
        self.s.send(str(q3).encode('utf-8'))
        print(f"Handshake info --> bank replied {self.s.recv(1024).decode('utf-8')}")
        self.s.send(str(q4).encode('utf-8'))
        print(f"Handshake info --> bank replied {self.s.recv(1024).decode('utf-8')}")
        
        checkpw = self.s.recv(4096).decode('utf-8')
        if self.scheme == 'rsa':
            checkpw = rsa.decrypt(int(checkpw), self.privkey)
        else:
            checkpwtmp = checkpw.strip("(").strip(")").split(",")
            checkpwtmp = [x.strip() for x in checkpwtmp] #take away tuple space or wierd stuff
            checkpwtmp = (int(checkpwtmp[0]), int(checkpwtmp[1])) 
            checkpw = elgamal.decrypt(checkpwtmp, self.privkey)
        checkpw = checkpw.split('-')
        if hash.sha256(checkpw[0]) == checkpw[1] and checkpw[0] == self.pw:
            self.s.send("good pw check".encode('utf-8'))
        else:
            self.s.send("pw check failed or msg tampered with".encode('utf-8'))
            raise Exception("pw check failed or msg tampered with")
        
        aestmp = self.aeskey + '-' + hash.sha256(self.aeskey)
        if self.scheme == 'rsa':
            aestmp = rsa.encrypt(aestmp, self.bankpubkey)
        else:
            aestmp = elgamal.encrypt(aestmp, self.bankpubkey)
        self.s.send(str(aestmp).encode('utf-8'))
        print(f"Handshake info --> AES key sent, bank replied {self.s.recv(1024).decode('utf-8')}")
        print("Handshake info --> ATM ready to go!")
        
    def send_user(): #need to hash, append to hash end of message, encrypt all, then send and check validity of hash in bank.py
        pass
    
    def send_pass(): #need to hash, append to hash end of message, encrypt all, then send and check validity of hash in bank.py
        pass

if __name__ == "__main__":
    # atmtest = ATM("Alex","alexpassword",["rsa"])
    atmtest2 = ATM("Owen","owenpassword",["elgamal"])
    # testatm = ATM("Owen","testpass", ['rsa'])
    atmtest2.starthandshake() 
