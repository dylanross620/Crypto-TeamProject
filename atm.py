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
        self.pw  = hash.sha256(password)
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
            if inp[1].isnumeric():
                sendstr += '-' + inp[1]
            elif inp[1].lower() == 'balance':
                sendstr += '-' + inp[1]
            else:
                print("invalid money amount")
                continue

            sendstr = str(self.counter) + '-' + sendstr
            #in bank, verify the hash including all dashes except the one right before the sha
            sendstr = aes.encrypt(sendstr + "-" + hash.sha256(sendstr),self.aeskey)
            self.s.send(sendstr.encode('utf-8'))

            bankret = self.s.recv(99999).decode('utf-8')#parse this out
            bankret = aes.decrypt(bankret,self.aeskey)
            bankret = bankret.split('-')
            self.countercheck(bankret)
            chkhash = bankret[-1]
            bankret.remove(chkhash)
            againsthash = '-'.join(bankret)
            bankret = bankret[1:]
            if hash.sha256(againsthash) != chkhash:
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
            q1 = q1 + '-' + hash.sha256(q1)
            # print(f"lenq{z}: {len(q1)} --> q{z}: {q1}")
            q1 = elgamal.encrypt(q1,self.bankpubkey)
            self.s.send(str(q1).encode('utf-8'))
            print(f"Handshake info (gamal) --> bank replied {self.s.recv(1024).decode('utf-8')}")

        q1 = pubkeystr[(pkeylen*17):]
        q1 = q1 + '-' + hash.sha256(q1)
        # print(f"lenq{17}: {len(q1)} --> q{17}: {q1}")
        q1 = elgamal.encrypt(q1,self.bankpubkey)
        self.s.send(str(q1).encode('utf-8'))
        print(f"Handshake info (gamal) --> bank replied {self.s.recv(1024).decode('utf-8')}")

        print("Handshake info --> starting password verification with bank")
        pwhash2 = self.pw
        pw1of2 = pwhash2[:len(pwhash2)//2]
        pw2of2 = pwhash2[len(pwhash2)//2:]
        pw1of2 = pw1of2 + '-' + hash.sha256(pw1of2)
        pw2of2 = pw2of2 + '-' + hash.sha256(pw2of2)
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
        aestmp1of2 = aestmp1of2 + '-' + hash.sha256(aestmp1of2)
        aestmp2of2 = aestmp2of2 + '-' + hash.sha256(aestmp2of2)
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
        q1 = q1 + '-' + hash.sha256(q1)
        q2 = q2 + '-' + hash.sha256(q2)
        q3 = q3 + '-' + hash.sha256(q3)
        q4 = q4 + '-' + hash.sha256(q4)
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
        pwhash2 = pwhash2 + '-' + hash.sha256(pwhash2)
        pwhash2 = rsa.encrypt(pwhash2, self.atmpubkey)
        self.s.send(str(pwhash2).encode('utf-8'))
        print(f"Handshake info --> bank responded with {self.s.recv(1024).decode('utf-8')}")
        print("Handshake info --> password verified with bank")
        aestmp = self.aeskey + '-' + hash.sha256(self.aeskey)
        aestmp = rsa.encrypt(aestmp, self.bankpubkey)
        self.s.send(str(aestmp).encode('utf-8'))
        print(f"Handshake info --> AES key sent, bank replied {self.s.recv(1024).decode('utf-8')}")

if __name__ == "__main__":
    # atmtest = ATM("Alex","alexpassword",["rsa"])
    atmtest2 = ATM("Owen","owenpassword",["elgamal"])
    # testatm = ATM("Owen","testpass", ['rsa'])
    atmtest2.starthandshake() 
