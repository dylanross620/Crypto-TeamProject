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
        if hash.sha1(q1[0]) == q1[1]:
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
        if hash.sha1(q2[0]) == q2[1]:
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
        if hash.sha1(q3[0]) == q3[1]:
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
        if hash.sha1(q4[0]) == q4[1]:
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
            if hash.sha1(q1[0]) == q1[1]:
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
        if clientname not in list(self.usertopass.keys()):
            raise Exception("Supplied atm username not in bank records")
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

        print("Handshake info --> verifying atm password")
        if self.scheme == 'rsa':
            checkpw = self.client.recv(4096).decode('utf-8')
            checkpw = rsa.decrypt(int(checkpw), self.privkey)
            checkpw = checkpw.split('-')
            if hash.sha1(checkpw[0]) == checkpw[1] and checkpw[0] == self.usertopass[clientname]:
                self.client.send("good pw check".encode('utf-8'))
            else:
                self.client.send("pw check failed or msg tampered with".encode('utf-8'))
                raise Exception("pw check failed or msg tampered with")
        else:
            checkpw = self.client.recv(4096).decode('utf-8')
            checkpwtmp = checkpw.strip("(").strip(")").split(",")
            checkpwtmp = [x.strip() for x in checkpwtmp] #take away tuple space or wierd stuff
            checkpwtmp = (int(checkpwtmp[0]), int(checkpwtmp[1])) 
            checkpw = elgamal.decrypt(checkpwtmp, self.privkey)
            checkpw = checkpw.split('-')
            if hash.sha1(checkpw[0]) == checkpw[1]:
                self.client.send("good pw check block 1/2".encode('utf-8'))
            else:
                self.client.send("pw check failed or msg tampered with block 1/2".encode('utf-8'))
                raise Exception("pw check failed or msg tampered with block 1/2")
            checkpwwhole = ""
            checkpwwhole += checkpw[0]
            checkpw = self.client.recv(4096).decode('utf-8')
            checkpwtmp = checkpw.strip("(").strip(")").split(",")
            checkpwtmp = [x.strip() for x in checkpwtmp] #take away tuple space or wierd stuff
            checkpwtmp = (int(checkpwtmp[0]), int(checkpwtmp[1])) 
            checkpw = elgamal.decrypt(checkpwtmp, self.privkey)
            checkpw = checkpw.split('-')
            if hash.sha1(checkpw[0]) == checkpw[1]:
                self.client.send("good pw check block 2/2".encode('utf-8'))
            else:
                self.client.send("pw check failed or msg tampered with block 2/2".encode('utf-8'))
                raise Exception("pw check failed or msg tampered with block 2/2")
            self.client.recv(4096) #need blocking call for pretty print
            checkpwwhole += checkpw[0]
            if checkpwwhole == self.usertopass[clientname]:
                self.client.send("good pw check with combined blocks".encode('utf-8'))
            else:
                self.client.send("pw check failed with all combined blocks".encode('utf-8'))
                raise Exception("pw check failed with all combined blocks")
        print("Handshake info --> good password verification")
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


import json
import hash
import socket
import ast
from PublicKey import rsa
from PublicKey import elgamal
from PrivateKey import aes
class ATM:
    def __init__(self, username, password, preflist = []):
        self.user = username
        self.pw  = hash.sha1(password)
        self.aeskey = aes.generate_key()
        if len(preflist) == 0:
            raise Exception("need to have preferences as the user to compare to server...")
        self.prefs = preflist
        self.scheme = None
        self.pubkey = None
        self.privkey = None
        self.bankpubkey = None
        self.counter = 1;
        self.s = socket.socket()
        self.s.connect(('127.0.0.1', 5432))

    def countercheck(self, msg):
        if(int(msg[0]) <= self.counter):
            raise Exception("counter check failed or msg tampered with")
        self.counter = int(msg[0]) + 1

    def post_handshake(self): #takes in user input to interact with bank indefinitely
        print("ATM")
        print("Example withdraw: 'withdraw [positive_int]'")
        print("Example deposit: 'deposit [positive_int]'")
        print("Example check: 'check balance'")
        print("To close ATM, type q")
        print("---------------------------------------------------")
        while True:
            inp = input("command: ")
            inp = inp.strip()
            if inp == 'q':
                break
            inp = inp.split(' ')
            sendstr = self.user + '-' + self.pw + '-'
            if len(inp) != 2:
                print("not a valid operation supported by bank")
                continue
            if inp[0].lower() == 'withdraw':
                sendstr += inp[0].lower()
            elif inp[0].lower() == 'deposit':
                sendstr += inp[0].lower()
            elif inp[0].lower() == 'check':
                sendstr += inp[0].lower()
            else:
                print("not a valid operation supported by bank")
                continue
            if inp[1].isnumeric() and int(inp[1]) > 0:
                sendstr += '-' + inp[1]
            elif inp[1].lower() == 'balance':
                sendstr += '-' + inp[1]
            else:
                print("invalid money amount")
                continue

            sendstr = str(self.counter) + '-' + sendstr
            #in bank, verify the hash including all dashes except the one right before the sha
            sendstr = aes.encrypt(sendstr + "-" + hash.sha1(sendstr),self.aeskey)
            self.s.send(sendstr.encode('utf-8'))

            bankret = self.s.recv(99999).decode('utf-8')#parse this out
            bankret = aes.decrypt(bankret,self.aeskey)
            bankret = bankret.split('-')
            try:
                self.countercheck(bankret)
            except Exception as e:
                print(str(e))
                continue
            chkhash = bankret[-1]
            bankret.remove(chkhash)
            againsthash = '-'.join(bankret)
            bankret = bankret[1:]
            if hash.sha1(againsthash) != chkhash:
                print("bank return msg integrity compromised")
                continue
            if bankret[0] != self.user:
                print("bank user return value tampered with")
                continue
            print(f"bank responded with '{bankret[2]}' to the request, money in account: {bankret[1]}") 
        self.s.close()

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
            bkeypairs = elgamal.load_keys("local_storage/bank-elgamal.txt",1024)
            self.bankpubkey = bkeypairs[0] # see above
        self.pubkey = keypairs[0]
        self.privkey = keypairs[1]
        print("Handshake info --> sending over atm pubkey...")
        if self.scheme == "rsa":
            self.send_pub_rsa()
        else:
            self.send_pub_gamal()

        print("Handshake info --> ATM ready to go!")
        self.post_handshake()

    def send_pub_gamal(self):
        pubkeystr = str(self.pubkey)
        pkeylen = len(pubkeystr) // 16
        for z in range(0,17):
            q1 = pubkeystr[(pkeylen*z):(pkeylen*(z+1))]
            q1 = q1 + '-' + hash.sha1(q1)
            # print(f"lenq{z}: {len(q1)} --> q{z}: {q1}")
            q1 = elgamal.encrypt(q1,self.bankpubkey)
            self.s.send(str(q1).encode('utf-8'))
            print(f"Handshake info (gamal) --> bank replied {self.s.recv(1024).decode('utf-8')}")

        q1 = pubkeystr[(pkeylen*17):]
        q1 = q1 + '-' + hash.sha1(q1)
        # print(f"lenq{17}: {len(q1)} --> q{17}: {q1}")
        q1 = elgamal.encrypt(q1,self.bankpubkey)
        self.s.send(str(q1).encode('utf-8'))
        print(f"Handshake info (gamal) --> bank replied {self.s.recv(1024).decode('utf-8')}")

        print("Handshake info --> starting password verification with bank")
        pwhash2 = self.pw
        pw1of2 = pwhash2[:len(pwhash2)//2]
        pw2of2 = pwhash2[len(pwhash2)//2:]
        pw1of2 = pw1of2 + '-' + hash.sha1(pw1of2)
        pw2of2 = pw2of2 + '-' + hash.sha1(pw2of2)
        pw1of2 = elgamal.encrypt(pw1of2, self.bankpubkey)
        pw2of2 = elgamal.encrypt(pw2of2, self.bankpubkey)
        self.s.send(str(pw1of2).encode('utf-8'))
        print(f"Handshake info --> bank responded with {self.s.recv(1024).decode('utf-8')}") #atm prints good block 1/2 and 2/2
        self.s.send(str(pw2of2).encode('utf-8'))
        print(f"Handshake info --> bank responded with {self.s.recv(1024).decode('utf-8')}") #atm prints good block 1/2 and 2/2
        self.s.send("breaker".encode('utf-8')) #need blocking call for pretty print
        print(f"Handshake info --> bank responded with {self.s.recv(1024).decode('utf-8')}")
        print("Handshake info --> password verified with bank")
        aestmp1of2 = self.aeskey[:len(self.aeskey)//2]
        aestmp2of2 = self.aeskey[len(self.aeskey)//2:]
        aestmp1of2 = aestmp1of2 + '-' + hash.sha1(aestmp1of2)
        aestmp2of2 = aestmp2of2 + '-' + hash.sha1(aestmp2of2)
        aestmp1of2 = elgamal.encrypt(aestmp1of2, self.bankpubkey)
        aestmp2of2 = elgamal.encrypt(aestmp2of2, self.bankpubkey)
        self.s.send(str(aestmp1of2).encode('utf-8'))
        print(f"Handshake info --> AES block 1/2 sent, bank replied {self.s.recv(1024).decode('utf-8')}") #bank replied good block
        self.s.send(str(aestmp2of2).encode('utf-8'))
        print(f"Handshake info --> AES block 2/2 sent, bank replied {self.s.recv(1024).decode('utf-8')}") #bank replied good block

    def send_pub_rsa(self):
        pubkeystr = str(self.pubkey)
        pkeylen = len(pubkeystr) // 4
        print(pkeylen)
        q1 = pubkeystr[0:pkeylen]
        q2 = pubkeystr[pkeylen:(pkeylen*2)]
        q3 = pubkeystr[(pkeylen*2):(pkeylen*3)]
        q4 = pubkeystr[(pkeylen*3):]
        q1 = q1 + '-' + hash.sha1(q1)
        q2 = q2 + '-' + hash.sha1(q2)
        q3 = q3 + '-' + hash.sha1(q3)
        q4 = q4 + '-' + hash.sha1(q4)
        q1 = rsa.encrypt(q1,self.bankpubkey)
        q2 = rsa.encrypt(q2,self.bankpubkey)
        q3 = rsa.encrypt(q3,self.bankpubkey)
        q4 = rsa.encrypt(q4,self.bankpubkey)
        self.s.send(str(q1).encode('utf-8'))
        print(f"Handshake info (rsa) --> bank replied {self.s.recv(1024).decode('utf-8')}")
        self.s.send(str(q2).encode('utf-8'))
        print(f"Handshake info (rsa) --> bank replied {self.s.recv(1024).decode('utf-8')}")
        self.s.send(str(q3).encode('utf-8'))
        print(f"Handshake info (rsa) --> bank replied {self.s.recv(1024).decode('utf-8')}")
        self.s.send(str(q4).encode('utf-8'))
        print(f"Handshake info (rsa) --> bank replied {self.s.recv(1024).decode('utf-8')}")

        print("Handshake info --> starting password verification")
        pwhash2 = self.pw
        pwhash2 = pwhash2 + '-' + hash.sha1(pwhash2)
        pwhash2 = rsa.encrypt(pwhash2, self.atmpubkey)
        self.s.send(str(pwhash2).encode('utf-8'))
        print(f"Handshake info --> bank responded with {self.s.recv(1024).decode('utf-8')}")
        print("Handshake info --> password verified with bank")
        aestmp = self.aeskey + '-' + hash.sha1(self.aeskey)
        aestmp = rsa.encrypt(aestmp, self.bankpubkey)
        self.s.send(str(aestmp).encode('utf-8'))
        print(f"Handshake info --> AES key sent, bank replied {self.s.recv(1024).decode('utf-8')}")

if __name__ == "__main__":
    # atmtest = ATM("Alex","alexpassword",["rsa"])
    atmtest2 = ATM("Owen","owenpassword",["elgamal"])
    # print(atmtest2.pw)
    # print(atmtest.pw)
    # testatm = ATM("Owen","testpass", ['rsa'])
    atmtest2.starthandshake() 

        


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