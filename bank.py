import json
import hash
import socket
import select
import threading
from PublicKey import rsa
from PublicKey import elgamal
from PrivateKey import aes

from atm import ATM


class Bank:
    def __init__(self):
        self.usertopass = json.loads(open("local_storage/usertohashpass.txt", "r").read()) #returns dict structured (user:hashpass)
        self.usertomoney = json.loads(open("local_storage/usertomoney.txt", "r").read()) #returns dict structured (user:plaintext_money)
        self.methods = ['rsa', 'elgamal'] #in order of preference
        print("Public key methods in use by bank --> ", self.methods)
        # self.read = rsa.load_keys("local_storage/bank-" + self.common + ".txt", 128)
        # self.server_random = secrets.token_bytes(4096)
        # self.atmrandom = None
        self.scheme = None
        self.pubkey = None
        self.privkey = None
        self.atmpubkey = None
        self.aeskey = None

        self.s = socket.socket()
        self.s.bind(('127.0.0.1',5432))
        self.s.listen(5)
        self.client = None
        self.clientaddr = None
    def addhashedpassword(self, username: str, password: str) :
        self.usertopass[username] = hash.sha256(password)
        open("local_storage/usertohashpass.txt", "w+").write(json.dumps(self.usertopass))

    def addusertomoney(self, username: str, amount: str): #adds info to runtime dict and dumps to file
        self.usertomoney[username] = amount
        open("local_storage/usertomoney.txt", "w+").write(json.dumps(self.usertomoney))

    def starthandshake(self): #encrypt username with atm public key, and send it back (deny connection if username doesnt exist)
        self.client, self.clientaddr = self.s.accept()
        clienthello = self.client.recv(1024)
        clienthello = clienthello.decode('utf-8').split('-')
        clientname = clienthello[0]
        atmprefs = eval(clienthello[1])
        print(f"ATM user '{clientname}' has initiated handshake, hello to BANK server!")
        atmprefs = [x.lower() for x in atmprefs]
        common = list(set(self.methods) & set(atmprefs))
        if len(common) == 0:
            raise Exception("no common methods between atm/bank")
        else:
            self.scheme = common[0]
        print(f"Handshake info --> common encryption scheme set to use {self.scheme}")
        keypairs = None
        if self.scheme == "rsa":
            keypairs = rsa.load_keys("local_storage/bank-rsa.txt", 4096)
        else:
            keypairs = elgamal.load_keys("local_storage/bank-elgamal.txt",4096)
        self.pubkey = keypairs[0]
        self.privkey = keypairs[1]
        self.client.send(self.scheme.encode('utf-8'))
        #we need to recieve atm pubkey in 2 parts now
        print("Handshake info --> recieving atm pubkey...")
        q1 = self.client.recv(4096)
        q1 = q1.decode('utf-8')
        if self.scheme == 'rsa':
            q1 = rsa.decrypt(int(q1), self.privkey)
        else:
            q1 = elgamal.decrypt(eval(q1), self.privkey)
        q1 = q1.split('-')
        if hash.sha256(q1[0]) == q1[1]:
            self.client.send("good first quarter recieved".encode('utf-8'))
        else:
            self.client.send("first quarter tampered".encode('utf-8'))
            raise Exception("first quarter tampered")

        q2 = self.client.recv(4096)
        q2 = q2.decode('utf-8')
        if self.scheme == 'rsa':
            q2 = rsa.decrypt(int(q2), self.privkey)
        else:
            q2 = elgamal.decrypt(eval(q2), self.privkey)
        q2 = q2.split('-')
        if hash.sha256(q2[0]) == q2[1]:
            self.client.send("good second quarter recieved".encode('utf-8'))
        else:
            self.client.send("second quarter tampered".encode('utf-8'))
            raise Exception("second quarter tampered")

        q3 = self.client.recv(4096)
        q3 = q3.decode('utf-8')
        if self.scheme == 'rsa':
            q3 = rsa.decrypt(int(q3), self.privkey)
        else:
            q3 = elgamal.decrypt(eval(q3), self.privkey)
        q3 = q3.split('-')
        if hash.sha256(q3[0]) == q3[1]:
            self.client.send("good third quarter recieved".encode('utf-8'))
        else:
            self.client.send("third quarter tampered".encode('utf-8'))
            raise Exception("third quarter tampered")

        q4 = self.client.recv(4096)
        q4 = q4.decode('utf-8')
        if self.scheme == 'rsa':
            q4 = rsa.decrypt(int(q4), self.privkey)
        else:
            q4 = elgamal.decrypt(eval(q4), self.privkey)
        q4 = q4.split('-')
        if hash.sha256(q4[0]) == q4[1]:
            self.client.send("good fourth quarter recieved".encode('utf-8'))
        else:
            self.client.send("fourth quarter tampered".encode('utf-8'))
            raise Exception("fourth quarter tampered")
        
        self.atmpubkey = q1[0]
        self.atmpubkey += q2[0]
        self.atmpubkey += q3[0]
        self.atmpubkey += q4[0]
        self.atmpubkey = eval(self.atmpubkey)
        print("Handshake info --> atm pubkey successully recieved")
    
if __name__ == "__main__":
    testbank = Bank()
    # testatm = ATM("testuser","testpass", ['rsa'])
    # testatm.starthandshake() 
    testbank.starthandshake()
    # testatm.starthandshake()
    print(testbank.usertopass)
    print(testbank.usertomoney)
    # test1 = threading.Thread(name='test1', target = testatm.starthandshake)
    # test2 = threading.Thread(name='test2', target = testbank.starthandshake)
    # test1.start()
    # test2.start()
    # print(testbank.keypairs)