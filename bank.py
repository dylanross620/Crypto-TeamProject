import json
import hash
import socket
import select
import ast
from PublicKey import rsa
from PublicKey import elgamal
from PrivateKey import aes

class Bank:
    def __init__(self):
        self.usertopass = json.loads(open("local_storage/usertohashpass.txt", "r").read()) #returns dict structured (user:hashpass)
        self.usertomoney = json.loads(open("local_storage/usertomoney.txt", "r").read()) #returns dict structured (user:plaintext_money)
        self.methods = ['rsa', 'elgamal'] #in order of preference
        print("Public key methods in use by bank --> ", self.methods)
        self.scheme = None
        self.pubkey = None
        self.privkey = None
        self.atmpubkey = None
        self.aeskey = None
        self.mackey = None
        self.counter = 0

        self.s = socket.socket()
        self.s.bind(('127.0.0.1',5432))
        self.s.listen(5)
        self.client = None
        self.clientaddr = None

    def addhashedpassword(self, username: str, password: str) :
        self.usertopass[username] = hash.sha1(password)
        open("local_storage/usertohashpass.txt", "w+").write(json.dumps(self.usertopass))

    def addusertomoney(self, username: str, amount: str): #adds info to runtime dict and dumps to file
        self.usertomoney[username] = amount
        open("local_storage/usertomoney.txt", "w+").write(json.dumps(self.usertomoney))

    def countercheck(self, msg):
        if(int(msg[0]) <= self.counter):
            raise Exception("counter check failed or msg tampered with")
        self.counter = int(msg[0]) + 1

    def withdraw(self,usr, amt): 
        #we include username/pw in the msg so we can auth and not just use self.clientname blindly (incase blackhat sends packets)
        #msg format --> [username-pw-withdraw/deposit-money]-msghash
        #sends back username-remaining_money-actualmsg-msghash
        sendback = usr + "-"
        if int(self.usertomoney[usr]) - amt < 0:
            sendback += self.usertomoney[usr] + '-' + "cannot overdraw this account"
            sendback = str(self.counter) + '-' + sendback
            sendback = aes.encrypt(sendback + '-' + hash.sha1(sendback),self.aeskey)
            self.client.send(sendback.encode('utf-8'))
        else:
            self.usertomoney[usr] = str(int(self.usertomoney[usr]) - amt)
            sendback += self.usertomoney[usr] + '-' + "withdraw successful"
            sendback = str(self.counter) + '-' + sendback
            sendback = aes.encrypt(sendback + '-' + hash.sha1(sendback),self.aeskey)
            self.client.send(sendback.encode('utf-8'))

    def deposit(self,usr, amt):
            sendback = usr + "-"
            self.usertomoney[usr] = str(int(self.usertomoney[usr]) + amt)
            sendback += self.usertomoney[usr] + '-' + "deposit successful"
            sendback = str(self.counter) + '-' + sendback
            sendback = aes.encrypt(sendback + '-' + hash.sha1(sendback),self.aeskey)
            self.client.send(sendback.encode('utf-8'))

    def check(self,usr):
            sendback = usr + "-"
            sendback += self.usertomoney[usr] + '-' + "check successful"
            sendback = str(self.counter) + '-' + sendback
            sendback = aes.encrypt(sendback + '-' + hash.sha1(sendback),self.aeskey)
            self.client.send(sendback.encode('utf-8'))
            
    def post_handshake(self):
        count = self.client.recv(4096).decode('utf-8')
        count = aes.decrypt(count,self.aeskey)
        count = count.split('-')
        chkhash = count[-1]
        count.remove(chkhash)
        againsthash = '-'.join(count)
        if hash.sha1(againsthash) != chkhash:
            sendback = "notverifieduser-0-msg integrity compromised"
            sendback = aes.encrypt(sendback + '-' + hash.sha1(sendback),self.aeskey)
            self.client.send(sendback.encode('utf-8'))
        if count[1] not in list(self.usertopass.keys()):
            sendback = "notverifieduser-0-username not known in bank"
            sendback = aes.encrypt(sendback + '-' + hash.sha1(sendback),self.aeskey)
            self.client.send(sendback.encode('utf-8'))
        if count[2] != self.usertopass[count[1]]:
            sendback = count[1] + "-"
            sendback += self.usertomoney[usr] + '-' + "password not matching in bank"
            sendback = aes.encrypt(sendback + '-' + hash.sha1(sendback),self.aeskey)
            self.client.send(sendback.encode('utf-8'))
        self.counter = int(count[0]) + 1
        sendback = str(self.counter) + '-' + count[1] + "-" + "counter exchange successful"
        sendback = aes.encrypt(sendback + '-' + hash.sha1(sendback),self.aeskey)
        self.client.send(sendback.encode('utf-8'))

        while True:
            cmd = self.client.recv(4096).decode('utf-8')
            if len(cmd) == 0:
                break
            cmd = aes.decrypt(cmd,self.aeskey)
            cmd = cmd.split('-')
            self.countercheck(cmd)
            chkhash = cmd[-1]
            cmd.remove(chkhash)
            againsthash = '-'.join(cmd)
            cmd = cmd[1:]
            if hash.sha1(againsthash) != chkhash:
                sendback = "notverifieduser-0-msg integrity compromised"
                sendback = str(self.counter) + '-' + sendback
                sendback = aes.encrypt(sendback + '-' + hash.sha1(sendback),self.aeskey)
                self.client.send(sendback.encode('utf-8'))
                continue
            if cmd[0] not in list(self.usertopass.keys()):
                sendback = "notverifieduser-0-username not known in bank"
                sendback = str(self.counter) + '-' + sendback
                sendback = aes.encrypt(sendback + '-' + hash.sha1(sendback),self.aeskey)
                self.client.send(sendback.encode('utf-8'))
                continue
            if cmd[1] != self.usertopass[cmd[0]]:
                sendback = cmd[0] + "-"
                sendback += self.usertomoney[usr] + '-' + "password not matching in bank"
                sendback = str(self.counter) + '-' + sendback
                sendback = aes.encrypt(sendback + '-' + hash.sha1(sendback),self.aeskey)
                self.client.send(sendback.encode('utf-8'))
                continue
            if cmd[2] == 'withdraw':
                self.withdraw(cmd[0],int(cmd[3]))
            elif cmd[2] == 'deposit':
                self.deposit(cmd[0],int(cmd[3]))
            elif cmd[2] == 'check':
                self.check(cmd[0])
            else:
                sendback = cmd[0] + "-"
                sendback += self.usertomoney[usr] + '-' + "invalid command"
                sendback = str(self.counter) + '-' + sendback
                sendback = aes.encrypt(sendback + '-' + hash.sha1(sendback),self.aeskey)
                self.client.send(sendback.encode('utf-8'))
            
        self.s.close()

    def starthandshake(self): #encrypt username with atm public key, and send it back (deny connection if username doesnt exist)
        self.client, self.clientaddr = self.s.accept()
        clienthello = self.client.recv(1024)
        clienthello = clienthello.decode('utf-8').split('-')
        print(clienthello)
        clientname = repr(clienthello[0]).strip("'")
        atmprefs = json.loads(clienthello[1])
        # if clientname not in list(self.usertopass.keys()):
        #     raise Exception("Supplied atm username not in bank records")
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
        #need to recieve mac key via asymmetric encryption
        print(f"Handshake info --> acquiring MAC key...")
        mactmp = self.client.recv(99999).decode('utf-8')
        if self.scheme == 'rsa':
            mactmp = rsa.decrypt(int(mactmp),self.privkey)
        else:
            mactmp = mactmp.strip("(").strip(")").split(",")
            mactmp = [x.strip() for x in mactmp] #take away tuple space or wierd stuff
            mactmp = (int(mactmp[0]), int(mactmp[1]))
            mactmp = elgamal.decrypt(mactmp,self.privkey)
        mactmp = mactmp.split('-')
        if hash.sha1(mactmp[0]) == mactmp[1]:
            self.client.send("good MAC key recieved".encode('utf-8'))
            self.mackey= mactmp[0]
        else:
            self.client.send("error in MAC key".encode('utf-8'))
            raise Exception("error in mac key")

        print("Handshake info --> MAC key acquired")
        print("Handshake info --> starting AES shared key transfer")
        if self.scheme == 'rsa':
            tmpaes = self.client.recv(4096).decode('utf-8')
            tmpaes = rsa.decrypt(int(tmpaes), self.privkey)
            tmpaes = tmpaes.split('-')
            if hash.sha1(tmpaes[0]) == tmpaes[1]:
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
            if hash.sha1(tmpaes1of2[0]) == tmpaes1of2[1]:
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
            if hash.sha1(tmpaes1of2[0]) == tmpaes1of2[1]:
                print("Handshake info --> AES key block 2/2 recieved")
                self.client.send("good block".encode('utf-8'))
                self.aeskey += tmpaes1of2[0]
            else:
                self.client.send("bad block".encode('utf-8'))
                raise Exception("AES key tampered with")

        ##----now for the atmpubkey
        print("Handshake info --> recieving atm pubkey...")
        atmpubtmp = self.client.recv(99999).decode('utf-8')
        atmpubtmp = aes.decrypt(atmpubtmp,self.aeskey)
        atmpubtmp = atmpubtmp.split('-')
        if hash.hmac(atmpubtmp[0],self.mackey) == atmpubtmp[1]:
            self.client.send("good atmkey recieved".encode('utf-8'))
        else:
            self.client.send("bad atmkey".encode('utf-8'))
            raise Exception("bad atmkey")
        
        if self.scheme == 'rsa':
            atmpubtmp = atmpubtmp[0].strip("(").strip(")").split(",")
            atmpubtmp = [x.strip() for x in atmpubtmp] #take away tuple space or wierd stuff
            self.atmpubkey = (int(atmpubtmp[0]), int(atmpubtmp[1]))
        else:
            atmpubtmp = atmpubtmp[0].strip("(").strip(")").split(",")
            atmpubtmp = [x.strip() for x in atmpubtmp] #take away tuple space or wierd stuff
            self.atmpubkey = (int(atmpubtmp[0]), int(atmpubtmp[1]), int(atmpubtmp[2]))
        
        print("Handshake info --> atm pubkey successully recieved")
        print("Handshake info --> Bank ready to go!")
        self.post_handshake()

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
