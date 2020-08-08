import json
import hash
import socket
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
        # self.s = socket.socket(socket.AFINET,socket.SOCK_STREAM)
        self.s = socket.socket()
        self.s.bind(('127.0.0.1',5432))
        self.s.listen(5)
        
        # self.s = socket.socket()
        # self.s.connect(('127.0.0.1', 5432))

        # self.s.settimeout(1)
        self.client = None
        self.clientaddr = None
        # print(self.server_random)
    def addhashedpassword(self, username: str, password: str) :
        self.usertopass[username] = hash.sha256(password)
        open("local_storage/usertohashpass.txt", "w+").write(json.dumps(self.usertopass))

    def addusertomoney(self, username: str, amount: str): #adds info to runtime dict and dumps to file
        self.usertomoney[username] = amount
        open("local_storage/usertomoney.txt", "w+").write(json.dumps(self.usertomoney))

    def starthandshake(self): #encrypt username with atm public key, and send it back (deny connection if username doesnt exist)
        self.client, self.clientaddr = self.s.accept()
        self.client.send("working FROM BANK".encode('utf-8'))
        # print("got connection from " + self.clientaddr[0])
        # self.client.close()
        # clienthello = self.s.recv(1024)
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
        print('here')
        # self.s.send((self.scheme + "-" +str(self.pubkey)).encode('utf-8'))
        self.client.send((self.scheme + "-" +str(self.pubkey)).encode('utf-8'))
        return True

if __name__ == "__main__":
    testbank = Bank()
    testatm = ATM("testuser","testpass", ['rsa'])
    testatm.starthandshake() 
    testbank.starthandshake()
    # testatm.starthandshake()
    print(testbank.usertopass)
    print(testbank.usertomoney)
    # print(testbank.keypairs)