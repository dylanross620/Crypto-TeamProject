import json
from PublicKey import rsa
from PublicKey import elgamal
import hash
from atm import ATM
import secrets

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
        # print(self.server_random)
    def addhashedpassword(self, username: str, password: str) :
        self.usertopass[username] = hash.sha256(password)
        open("local_storage/usertohashpass.txt", "w+").write(json.dumps(self.usertopass))

    def addusertomoney(self, username: str, amount: str): #adds info to runtime dict and dumps to file
        self.usertomoney[username] = amount
        open("local_storage/usertomoney.txt", "w+").write(json.dumps(self.usertomoney))

    def starthandshake(self, atminstance): #encrypt username with atm public key, and send it back (deny connection if username doesnt exist)
        print(f"ATM user '{atminstance.user}' has initiated handshake, hello to BANK server!")
        #we now take in the client random byte string, client supported encryptions, and 
        # self.atmrandom = atminstance.client_random
        # print(f"Handshake info --> client random recieved in plaintext as {clientrand}")
        print(f"Handshake info --> client supported schemes {atminstance.prefs}")
        print(f"Handshake info --> starting server hello...")
        atmpreflist = [x.lower() for x in atminstance.prefs]
        common = list(set(self.methods) & set(atmpreflist))
        if len(common) == 0:
            raise Exception("no common methods between atm/bank")
        else:
            self.scheme = common[0]
        atminstance.scheme = self.scheme
        print(f"Handshake info --> common encryption scheme set to use {self.scheme}")
        keypairs = None
        if self.scheme == "rsa":
            keypairs = rsa.load_keys("local_storage/bank-rsa.txt", 4096)
        else:
            keypairs = elgamal.load_keys("local_storage/bank-elgamal.txt",4096)
        self.pubkey = keypairs[0]
        self.privkey = keypairs[1]
        atminstance.key_setup(self.pubkey)
        self.atmpubkey = atminstance.pubkey
        # print(f"Handshake info --> server random sent in plaintext as {self.server_random}")
        # atminstance.bankrandom = self.server_random


if __name__ == "__main__":
    testbank = Bank()
    testatm = ATM("testuser","testpass", ['rsa'])
    testbank.starthandshake(testatm)
    print(testbank.usertopass)
    print(testbank.usertomoney)
    # print(testbank.keypairs)