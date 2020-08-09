import json
import hash
import socket
import select
import ast
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

    def withdraw(msg): 
        #we include username/pw in the msg so we can auth and not just use self.clientname blindly (incase blackhat sends packets)
        #msg format --> username-pw-money-msghash
        #sends back username-remaining_money-msghash
        pass

    def deposit(msg):
        pass

    def rec_atmpub_rsa(self):
        q1 = self.client.recv(4096)
        q1 = q1.decode('utf-8')
        if self.scheme == 'rsa':
            q1 = rsa.decrypt(int(q1), self.privkey)
        else:
            q1tmp = q1.strip("(").strip(")").split(",")
            q1tmp = [x.strip() for x in q1tmp] #take away tuple space or wierd stuff
            q1tmp = (int(q1tmp[0]), int(q1tmp[1])) 
            q1 = elgamal.decrypt(q1tmp, self.privkey)
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
            q2tmp = q2.strip("(").strip(")").split(",")
            q2tmp = [x.strip() for x in q2tmp] #take away tuple space or wierd stuff
            q2tmp = (int(q2tmp[0]), int(q2tmp[1])) 
            q2 = elgamal.decrypt(q2tmp, self.privkey)
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
            q3tmp = q3.strip("(").strip(")").split(",")
            q3tmp = [x.strip() for x in q3tmp] #take away tuple space or wierd stuff
            q3tmp = (int(q3tmp[0]), int(q3tmp[1])) 
            q3 = elgamal.decrypt(q3tmp, self.privkey)
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
            q4tmp = q4.strip("(").strip(")").split(",")
            q4tmp = [x.strip() for x in q4tmp] #take away tuple space or wierd stuff
            q4tmp = (int(q4tmp[0]), int(q4tmp[1])) 
            q4 = elgamal.decrypt(q4tmp, self.privkey)
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
        apubtmp = self.atmpubkey.strip("(").strip(")").split(",")
        apubtmp = [x.strip() for x in apubtmp] #take away tuple space or wierd stuff
        self.atmpubkey = (int(apubtmp[0]), int(apubtmp[1]))

    def rec_atmpub_gamal(self):
        self.atmpubkey = ""
        for z in range(0,18):
            q1 = self.client.recv(4096)
            q1 = q1.decode('utf-8')
            q1tmp = q1.strip("(").strip(")").split(",")
            q1tmp = [x.strip() for x in q1tmp] #take away tuple space or wierd stuff
            q1tmp = (int(q1tmp[0]), int(q1tmp[1])) 
            q1 = elgamal.decrypt(q1tmp, self.privkey)
            q1 = q1.split('-')
            if hash.sha256(q1[0]) == q1[1]:
                self.client.send(f"good block {z}/17 recieved".encode('utf-8'))
            else:
                self.client.send(f"{z}/17 tampered".encode('utf-8'))
                raise Exception(f"{z}/17 tampered")

            self.atmpubkey += q1[0]

        apubtmp = self.atmpubkey.strip("(").strip(")").split(",")
        apubtmp = [x.strip() for x in apubtmp] #take away tuple space or wierd stuff
        self.atmpubkey = (int(apubtmp[0]), int(apubtmp[1]), int(apubtmp[2]))

    def starthandshake(self): #encrypt username with atm public key, and send it back (deny connection if username doesnt exist)
        self.client, self.clientaddr = self.s.accept()
        clienthello = self.client.recv(1024)
        clienthello = clienthello.decode('utf-8').split('-')
        print(clienthello)
        clientname = repr(clienthello[0]).strip("'")
        atmprefs = json.loads(clienthello[1])
        print(f"ATM user " + clientname + " has initiated handshake, hello to BANK server!")
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
            keypairs = elgamal.load_keys("local_storage/bank-elgamal.txt",1024)
        self.pubkey = keypairs[0]
        self.privkey = keypairs[1]
        self.client.send(self.scheme.encode('utf-8'))
        #we need to recieve atm pubkey in 2 parts now
        print("Handshake info --> recieving atm pubkey...")
        
        if self.scheme == 'rsa':
            self.rec_atmpub_rsa()
        else:
            self.rec_atmpub_gamal()
            
        print("Handshake info --> atm pubkey successully recieved")
        print("Handshake info --> verifying bank to atm")
        if clientname not in list(self.usertopass.keys()):
            raise Exception("Supplied atm username not in bank records")
        pwhash2 = self.usertopass[clientname]
        if self.scheme == 'rsa':
            pwhash2 = pwhash2 + '-' + hash.sha256(pwhash2)
            pwhash2 = rsa.encrypt(pwhash2, self.atmpubkey)
            self.client.send(str(pwhash2).encode('utf-8'))
            print(f"Handshake info --> atm responded with {self.client.recv(1024).decode('utf-8')}")
        else:
            pw1of2 = pwhash2[:len(pwhash2)//2]
            pw2of2 = pwhash2[len(pwhash2)//2:]
            pw1of2 = pw1of2 + '-' + hash.sha256(pw1of2)
            pw2of2 = pw2of2 + '-' + hash.sha256(pw2of2)
            pw1of2 = elgamal.encrypt(pw1of2, self.atmpubkey)
            pw2of2 = elgamal.encrypt(pw2of2, self.atmpubkey)
            self.client.send(str(pw1of2).encode('utf-8'))
            print(f"Handshake info --> atm responded with {self.client.recv(1024).decode('utf-8')}") #atm prints good block 1/2 and 2/2
            self.client.send(str(pw2of2).encode('utf-8'))
            print(f"Handshake info --> atm responded with {self.client.recv(1024).decode('utf-8')}") #atm prints good block 1/2 and 2/2
            self.client.send("breaker".encode('utf-8')) #need blocking call for pretty print
            print(f"Handshake info --> atm responded with {self.client.recv(1024).decode('utf-8')}")

        print("Handshake info --> starting AES shared key transfer")
        if self.scheme == 'rsa':
            tmpaes = self.client.recv(4096).decode('utf-8')
            tmpaes = rsa.decrypt(int(tmpaes), self.privkey)
            tmpaes = tmpaes.split('-')
            if hash.sha256(tmpaes[0]) == tmpaes[1]:
                print("Handshake info --> AES key recieved")
                self.client.send("good AES key".encode('utf-8'))
                self.aeskey = tmpaes[0]
            else:
                self.client.send("AES key tampered with".encode('utf-8'))
                raise Exception("AES key tampered with")
        else:
            self.aeskey = ""
            tmpaes1of2 = self.client.recv(4096).decode('utf-8').strip("(").strip(")").split(",")
            tmpaes1of2 = [x.strip() for x in tmpaes1of2]
            tmpaes1of2 = (int(tmpaes1of2[0]), int(tmpaes1of2[1])) 
            tmpaes1of2 = elgamal.decrypt(tmpaes1of2, self.privkey)
            tmpaes1of2 = tmpaes1of2.split('-')
            if hash.sha256(tmpaes1of2[0]) == tmpaes1of2[1]:
                print("Handshake info --> AES key block 1/2 recieved")
                self.client.send("good block".encode('utf-8'))
                self.aeskey += tmpaes1of2[0]
            else:
                self.client.send("bad block".encode('utf-8'))
                raise Exception("AES key tampered with")

            tmpaes1of2 = self.client.recv(4096).decode('utf-8').strip("(").strip(")").split(",")
            tmpaes1of2 = [x.strip() for x in tmpaes1of2]
            tmpaes1of2 = (int(tmpaes1of2[0]), int(tmpaes1of2[1])) 
            tmpaes1of2 = elgamal.decrypt(tmpaes1of2, self.privkey)
            tmpaes1of2 = tmpaes1of2.split('-')
            if hash.sha256(tmpaes1of2[0]) == tmpaes1of2[1]:
                print("Handshake info --> AES key block 2/2 recieved")
                self.client.send("good block".encode('utf-8'))
                self.aeskey += tmpaes1of2[0]
            else:
                self.client.send("bad block".encode('utf-8'))
                raise Exception("AES key tampered with")


        print("Handshake info --> Bank ready to go!")

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
