import json
import hash
import socket
import select
import secrets
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
        self.p= 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
        self.dhprivateaes = secrets.randbelow(((self.p - 1) // 2)+1)
        self.dhprivatemac = secrets.randbelow(((self.p - 1) // 2)+1)
        self.serverrandom = secrets.token_bytes(32)
        self.s = socket.socket()
        self.s.bind(('127.0.0.1',5432))
        self.s.listen(5)
        self.client = None
        self.clientaddr = None

    def addhashedpassword(self, username: str, password: str): #for testing use only, you shouldn't be able to create bank account at atm
        self.usertopass[username] = hash.sha1(password)
        open("local_storage/usertohashpass.txt", "w+").write(json.dumps(self.usertopass))

    def addusertomoney(self, username: str, amount: str): #for testing use only
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
            sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback,self.mackey),self.aeskey)
            self.client.send(sendback.encode('utf-8'))
        else:
            self.usertomoney[usr] = str(int(self.usertomoney[usr]) - amt)
            open("local_storage/usertomoney.txt", "w+").write(json.dumps(self.usertomoney))
            sendback += self.usertomoney[usr] + '-' + "withdraw successful"
            sendback = str(self.counter) + '-' + sendback
            sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback,self.mackey),self.aeskey)
            self.client.send(sendback.encode('utf-8'))

    def deposit(self,usr, amt):
            sendback = usr + "-"
            self.usertomoney[usr] = str(int(self.usertomoney[usr]) + amt)
            open("local_storage/usertomoney.txt", "w+").write(json.dumps(self.usertomoney))
            sendback += self.usertomoney[usr] + '-' + "deposit successful"
            sendback = str(self.counter) + '-' + sendback
            sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback,self.mackey),self.aeskey)
            self.client.send(sendback.encode('utf-8'))

    def check(self,usr):
            sendback = usr + "-"
            sendback += self.usertomoney[usr] + '-' + "check successful"
            sendback = str(self.counter) + '-' + sendback
            sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback,self.mackey),self.aeskey)
            self.client.send(sendback.encode('utf-8'))
            
    def post_handshake(self):
        loggedin = False
        loginname = ""
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
            if hash.hmac(againsthash,self.mackey) != chkhash:
                sendback = "notverifieduser-0-msg integrity compromised"
                sendback = str(self.counter) + '-' + sendback
                sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback,self.mackey),self.aeskey)
                self.client.send(sendback.encode('utf-8'))
                continue
            if cmd[0] not in list(self.usertopass.keys()):
                sendback = "notverifieduser-0-username not known in bank(tampered name error)"
                sendback = str(self.counter) + '-' + sendback
                sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback,self.mackey),self.aeskey)
                self.client.send(sendback.encode('utf-8'))
                continue
            if cmd[1] == 'withdraw' and loggedin:
                self.withdraw(cmd[0],int(cmd[2]))
            elif cmd[1] == 'deposit' and loggedin:
                self.deposit(cmd[0],int(cmd[2]))
            elif cmd[1] == 'check' and loggedin:
                self.check(cmd[0])
            elif cmd[1] == 'login':
                if cmd[0] not in list(self.usertopass.keys()):
                    sendback = "notverifieduser-0-username not known in bank"
                    sendback = str(self.counter) + '-' + sendback
                    sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback,self.mackey),self.aeskey)
                    self.client.send(sendback.encode('utf-8'))
                if cmd[2] != self.usertopass[cmd[0]]:
                    sendback = cmd[0] + "-0-password not matching in bank"
                    sendback = str(self.counter) + '-' + sendback
                    sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback,self.mackey),self.aeskey)
                    self.client.send(sendback.encode('utf-8'))
                loggedin = True
                loginname = cmd[0]
                sendback = loginname + "-"
                sendback += self.usertomoney[loginname] + '-' + "login successful"
                sendback = str(self.counter) + '-' + sendback
                sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback,self.mackey),self.aeskey)
                self.client.send(sendback.encode('utf-8'))
            else:
                if loggedin:
                    sendback = loginname + "-"
                    sendback += self.usertomoney[loginname] + '-' + "invalid command"
                else:
                    sendback = "not_logged_in-0-LOGIN command not sent"
                sendback = str(self.counter) + '-' + sendback
                sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback,self.mackey),self.aeskey)
                self.client.send(sendback.encode('utf-8'))
            
        self.s.close()

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
            self.s.close()
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
        print("Handshake info --> recieving client random")
        clirand = self.client.recv(4096).decode('utf-8')
        print("Handshake info --> signing client random, server random, and DH parameters")
        clisign = str(clirand) + '-' + str(self.serverrandom) + '-' + str(pow(2, self.dhprivateaes, self.p)) + '-' + str(pow(2, self.dhprivatemac, self.p))
        clie = None
        if self.scheme == 'rsa':
            clie = rsa.sign(clisign,self.privkey)
        else:
            clie = elgamal.sign(clisign,self.privkey, self.pubkey)
        self.client.send(str(clisign).encode('utf-8'))
        print(f"Handshake info --> client says {self.client.recv(4096).decode('utf-8')}")
        self.client.send(str(clie).encode('utf-8'))
        print(f"Handshake info --> client says {self.client.recv(4096).decode('utf-8')}")
        self.client.send("breaker".encode('utf-8'))#formatting
        cliplain = self.client.recv(99999).decode('utf-8')
        cliplain = cliplain.split('-')
        self.aeskey = pow(int(cliplain[0]),self.dhprivateaes,self.p) % pow(2,256)
        self.mackey = pow(int(cliplain[1]),self.dhprivatemac,self.p) % pow(2,256)
        self.aeskey = str(hex(self.aeskey))[2:]
        self.mackey = str(hex(self.mackey))[2:]
        print("Handshake info --> bank calculated aes/mac keys from DH exchange")
        print(f"Handshake info --> Bank ready to go, atm replied {aes.decrypt(self.client.recv(1024).decode('utf-8'),self.aeskey)}")
        self.client.send((aes.encrypt("finished",self.aeskey)).encode('utf-8'))
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
