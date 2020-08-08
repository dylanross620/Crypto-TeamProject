from bank import Bank
from atm import ATM
import socket
import select
import threading

# bank = Bank()
# atm = ATM()
s = socket.socket()
s.bind(('127.0.0.1',5432))
s.listen(5)

testbank = Bank()
bank, bankaddr = s.accept()

testatm = ATM("testuser","testpass", ['rsa'])
client,clientaddr = s.accept()

test1 = threading.Thread(name='test1', target = testatm.starthandshake)
test2 = threading.Thread(name='test2', target = testbank.starthandshake)
test1.start()
test2.start()
# atmdone = testatm.starthandshake() #testatm has to start handshake before server in driver!
# bankdone = testbank.starthandshake()
print(testbank.usertopass)
print(testbank.usertomoney)

while True:
    sall = [s,bank,client]
    readers, writers, broken = select.select(sall,sall,sall)
    for r in readers:
        if r == bank:
        
        else if r == client:

        


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
        aestmp = atminstance.key_setup(self.pubkey)
        self.atmpubkey = atminstance.pubkey
        if self.scheme == "rsa":
            aestmp = rsa.decrypt(aestmp,self.privkey)
        else:
            aestmp = elgamal.decrypt(aestmp,self.privkey)
        #WHY DOES AESTEP HAVE BUNCH OF \x00 BEFORE IT? DOES DOING .strip('\x00') WORK FOR ALL INSTANCES OF THIS PROBLEM???
        keylen = len(aestmp) - 64
        reckey = aestmp[0:keylen]
        rechash = aestmp[-64:]

        reckey = reckey.strip('\x00') #will this break on blackhat team computer? why do the \x00's occur?

        print(repr("full decryted key+hash: " + aestmp)) #testing ---------- delete later

        if hash.sha256(reckey) == rechash: #HMAC is valid, we can use this key
            self.aeskey = reckey
        else:
            raise Exception("handshake exception --> AES KEY TAMPERED WITH")
        
        print("Handshake info --> AES secret key sucessfully shared")