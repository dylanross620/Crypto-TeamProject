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
        self.aeskey = None
        self.mackey = None
        self.counter = 0
        self.p= 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
        self.s = socket.socket()
        self.s.bind(('127.0.0.1',5432))
        self.s.listen(5)
        self.client = None
        self.clientaddr = None

    def countercheck(self, msg):
        if(int(msg[0]) <= self.counter):
            raise Exception("counter check failed or msg tampered with")
        self.counter = int(msg[0]) + 1

    def withdraw(self, usr, amt): 
        #we include username/pw in the msg so we can auth and not just use self.clientname blindly (incase blackhat sends packets)
        #msg format --> [username-pw-withdraw/deposit-money]-msghash
        #sends back username-remaining_money-actualmsg-msghash
        sendback = usr + "-"
        if int(self.usertomoney[usr]) - amt < 0:
            sendback += self.usertomoney[usr] + '-' + "cannot overdraw this account"
            sendback = str(self.counter) + '-' + sendback
            sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
            self.client.send(sendback.encode('utf-8'))
        else:
            self.usertomoney[usr] = str(int(self.usertomoney[usr]) - amt)
            open("local_storage/usertomoney.txt", "w+").write(json.dumps(self.usertomoney))
            sendback += self.usertomoney[usr] + '-' + "withdraw successful"
            sendback = str(self.counter) + '-' + sendback
            sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
            self.client.send(sendback.encode('utf-8'))

    def deposit(self, usr, amt):
        sendback = usr + "-"
        self.usertomoney[usr] = str(int(self.usertomoney[usr]) + amt)
        open("local_storage/usertomoney.txt", "w+").write(json.dumps(self.usertomoney))
        sendback += self.usertomoney[usr] + '-' + "deposit successful"
        sendback = str(self.counter) + '-' + sendback
        sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
        self.client.send(sendback.encode('utf-8'))

    def check(self, usr):
        sendback = usr + "-"
        sendback += self.usertomoney[usr] + '-' + "check successful"
        sendback = str(self.counter) + '-' + sendback
        sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
        self.client.send(sendback.encode('utf-8'))
            
    def post_handshake(self):
        # Initialize counter to a random number, as determined by client
        count = self.client.recv(4096).decode('utf-8')
        count = aes.decrypt(count,self.aeskey)
        count = count.split('-')

        chkhash = count[-1]
        count.remove(chkhash)
        againsthash = '-'.join(count)

        # Ensure message wasn't tampered with
        if hash.hmac(againsthash, self.mackey) != chkhash:
            sendback = "notverifieduser-0-msg integrity compromised"
            sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
            self.client.send(sendback.encode('utf-8'))

        self.counter = int(count[0]) + 1
        sendback = str(self.counter) + '-' + "counter exchange successful"
        sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
        self.client.send(sendback.encode('utf-8'))

        # User starts as not being logged in, wait for attempt to log in
        loggedin = False
        loginname = ""
        while True:
            cmd = self.client.recv(4096).decode('utf-8')
            if len(cmd) == 0:
                # Socket is closed
                self.s.close() 
                return

            cmd = aes.decrypt(cmd, self.aeskey)
            cmd = cmd.split('-')
            # Ensure message isn't a replay
            try:
                self.countercheck(cmd)
            except Exception as e:
                print(str(e))
                break           

            chkhash = cmd[-1]
            cmd.remove(chkhash)
            againsthash = '-'.join(cmd)

            # Ensure message not tampered with
            if chkhash != hash.hmac(againsthash, self.mackey):
                sendback = 'notverifieduser-0-message tampered'
                sendback = str(self.counter) + '-' + sendback
                senback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
                self.client.send(sendback.encode('utf-8'))
                continue

            cmd = cmd[1:]
            # Check if username is valid
            if cmd[0] not in list(self.usertopass.keys()):
                sendback = "notverifieduser-0-username not known in bank"
                sendback = str(self.counter) + '-' + sendback
                sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
                self.client.send(sendback.encode('utf-8'))
                continue

            # Check if password is correct
            if cmd[1] != self.usertopass[cmd[0]]:
                sendback = cmd[0] + "-0-password not matching in bank"
                sendback = str(self.counter) + '-' + sendback
                sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
                self.client.send(sendback.encode('utf-8'))
                continue

            # Login was successful, update atm
            loggedin = True
            loginname = cmd[0]
            sendback = loginname + "-"
            sendback += self.usertomoney[loginname] + '-' + "login successful"
            sendback = str(self.counter) + '-' + sendback
            sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
            self.client.send(sendback.encode('utf-8'))
            break
        

        while True:
            cmd = self.client.recv(4096).decode('utf-8')
            if len(cmd) == 0:
                # Socket was closed
                break

            cmd = aes.decrypt(cmd,self.aeskey)
            cmd = cmd.split('-')
            # Ensure message isn't a replay
            try:
                self.countercheck(cmd)
            except Exception as e:
                print(str(e))
                break           

            chkhash = cmd[-1]
            cmd.remove(chkhash)
            againsthash = '-'.join(cmd)
            cmd = cmd[1:]

            # Check if message was tampered with
            if hash.hmac(againsthash,self.mackey) != chkhash:
                sendback = "notverifieduser-0-msg integrity compromised"
                sendback = str(self.counter) + '-' + sendback
                sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
                self.client.send(sendback.encode('utf-8'))
                continue

            # Check that user name hasn't been modified
            if cmd[0] not in list(self.usertopass.keys()):
                sendback = "notverifieduser-0-username not known in bank(tampered name error)"
                sendback = str(self.counter) + '-' + sendback
                sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
                self.client.send(sendback.encode('utf-8'))
                continue

            #Check what the command is and do appropriate action
            if cmd[1] == 'withdraw' and loggedin:
                self.withdraw(cmd[0], int(cmd[2]))
            elif cmd[1] == 'deposit' and loggedin:
                self.deposit(cmd[0], int(cmd[2]))
            elif cmd[1] == 'check' and loggedin:
                self.check(cmd[0])
            else:
                # Error parsing command, send message back
                sendback = loginname + "-"
                sendback += self.usertomoney[loginname] + '-' + "invalid command"
                sendback = str(self.counter) + '-' + sendback
                sendback = aes.encrypt(sendback + '-' + hash.hmac(sendback, self.mackey), self.aeskey)
                self.client.send(sendback.encode('utf-8'))
            
        self.s.close()

    def starthandshake(self): #encrypt username with atm public key, and send it back (deny connection if username doesnt exist)
        self.client, self.clientaddr = self.s.accept()

        clienthello = self.client.recv(1024)
        clienthello = clienthello.decode('utf-8').split('-')
        atmprefs = json.loads(clienthello[0])
        print("ATM has initiated handshake, hello to BANK server!")

        # Parse hello message to select which PKC to use
        atmprefs = [x.lower() for x in atmprefs]
        common = list(set(self.methods) & set(atmprefs))
        scheme = None
        if len(common) == 0:
            self.client.close()
            raise Exception("no common methods between atm/bank")
        else:
            scheme = common[0]
        print(f"Handshake info --> common encryption scheme set to use {scheme}")

        # Load correct keys for selected system
        keypairs = None
        if scheme == "rsa":
            keypairs = rsa.load_keys("local_storage/bank-rsa.txt", 4096)
        else:
            keypairs = elgamal.load_keys("local_storage/bank-elgamal.txt", 1024)
        pubkey = keypairs[0]
        privkey = keypairs[1]
        # Tell atm which scheme to use
        self.client.send(scheme.encode('utf-8'))

        # Begin Diffie-Hellman
        print("Handshake info --> recieving client random")
        clirand = self.client.recv(4096).decode('utf-8')
        print("Handshake info --> signing client random, server random, and DH parameters")
        dhprivateaes = secrets.randbelow(((self.p - 1) // 2) + 1)
        dhprivatemac = secrets.randbelow(((self.p - 1) // 2) + 1)

        # Generate our DH values for both aes key and mac key. Send to client along with their values to ensure we received it properly
        clisign = str(clirand) + '-' + str(pow(2, dhprivateaes, self.p)) + '-' + str(pow(2, dhprivatemac, self.p))
        # Sign the message so atm knows it came from bank
        clie = None
        if scheme == 'rsa':
            clie = rsa.sign(clisign, privkey)
        else:
            clie = elgamal.sign(clisign, privkey, pubkey)

        self.client.send(str(clisign).encode('utf-8'))
        print(f"Handshake info --> client says {self.client.recv(4096).decode('utf-8')}")
        self.client.send(str(clie).encode('utf-8'))
        print(f"Handshake info --> client says {self.client.recv(4096).decode('utf-8')}")

        self.client.send("breaker".encode('utf-8'))#formatting

        # Use the DH values sent from atm previously to calculate the keys
        cliplain = clirand.split('-')
        self.aeskey = pow(int(cliplain[0]), dhprivateaes, self.p) % pow(2,256)
        self.mackey = pow(int(cliplain[1]), dhprivatemac, self.p) % pow(2,256)
        self.aeskey = format(self.aeskey, '064x')
        self.mackey = format(self.mackey, '064x')
        print("Handshake info --> bank calculated aes/mac keys from DH exchange")
        print(f"Handshake info --> Bank ready to go, atm replied {aes.decrypt(self.client.recv(1024).decode('utf-8'),self.aeskey)}")

        # Tell client we have the keys
        self.client.send((aes.encrypt("finished", self.aeskey)).encode('utf-8'))

        # Challenge client to see if they're an ATM
        client_keyname = aes.decrypt(self.client.recv(1024).decode('utf-8'), self.aeskey)
        challenge = format(secrets.randbits(20*8), '040x')

        if scheme == 'rsa':
            client_pubkey = rsa.load_public_key(f"local_storage/{client_keyname}-rsa.pub")
            challenge_encrypted = rsa.encrypt(challenge, client_pubkey)
        else:
            client_pubkey = elgamal.load_public_key(f"local_storage/{client_keyname}-elgamal.pub")
            challenge_encrypted = elgamal.encrypt(challenge, client_pubkey)

        self.client.send(aes.encrypt(str(challenge_encrypted), self.aeskey).encode('utf-8')) 

        client_response = aes.decrypt(self.client.recv(1024).decode('utf-8'), self.aeskey)
        if client_response != hash.sha1(challenge + self.aeskey):
            self.client.close()
            raise Exception("client is not an atm")

        self.post_handshake()

if __name__ == "__main__":
    testbank = Bank()
    testbank.starthandshake()
