import json
import hash
import socket
import ast
import secrets
from PublicKey import rsa
from PublicKey import elgamal
from PrivateKey import aes
class ATM:
    def __init__(self, username, password, preflist = []):
        self.user = username
        self.pw  = hash.sha1(password)
        self.aeskey = aes.generate_key()
        self.mackey = hash.generate_mac_key()
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
        self.counter = secrets.randbelow(pow(2, 2048))
        sendstr = str(self.counter) + '-' + self.user + '-' + self.pw
        sendstr = aes.encrypt(sendstr + "-" + hash.sha1(sendstr),self.aeskey)
        self.s.send(sendstr.encode('utf-8'))

        bankret = self.s.recv(99999).decode('utf-8')#parse this out
        bankret = aes.decrypt(bankret,self.aeskey)
        bankret = bankret.split('-')
        try:
            self.countercheck(bankret)
        except Exception as e:
            print(str(e))
        chkhash = bankret[-1]
        bankret.remove(chkhash)
        againsthash = '-'.join(bankret)
        bankret = bankret[1:]
        if hash.sha1(againsthash) != chkhash:
            print("bank return msg integrity compromised")
        if bankret[0] != self.user:
            print("bank user return value tampered with")
        print(f"Counter set, bank replied with '{bankret[1]}'")

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
        print("Handshake info --> sending MAC key to bank...")
        macsender = self.mackey + '-' + hash.sha1(self.mackey)
        if self.scheme == 'rsa':
            macsender = rsa.encrypt(macsender,self.bankpubkey)
        else:
            macsender = elgamal.encrypt(macsender,self.bankpubkey)
        self.s.send(str(macsender).encode('utf-8'))
        print(f"Handshake info --> bank returned {self.s.recv(4096).decode('utf-8')}")
        print("Handshake info --> sending AES key...")
        if self.scheme == 'rsa':
            aestmp = self.aeskey + '-' + hash.sha1(self.aeskey)
            aestmp = rsa.encrypt(aestmp, self.bankpubkey)
            self.s.send(str(aestmp).encode('utf-8'))
            print(f"Handshake info --> AES key sent, bank replied {self.s.recv(1024).decode('utf-8')}")
        else:
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

        print("Handshake info --> sending over atm pubkey...")
        pubkeysender = aes.encrypt((str(self.pubkey) + '-' + hash.hmac(str(self.pubkey),self.mackey)),self.aeskey)
        self.s.send(pubkeysender.encode('utf-8'))
        pubkeyret = self.s.recv(4096).decode('utf-8')
        print(f"Handshake info --> bank returned {pubkeyret}")
        print("Handshake info --> ATM ready to go!")
        self.post_handshake()

if __name__ == "__main__":
    # atmtest = ATM("Alex","alexpassword",["rsa"])
    atmtest2 = ATM("Owen","owenpassword",["elgamal"])
    # print(atmtest2.pw)
    # print(atmtest.pw)
    # testatm = ATM("Owen","testpass", ['rsa'])
    atmtest2.starthandshake() 
