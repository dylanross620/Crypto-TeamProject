import json
import hash
import socket
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
        self.p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
        self.dhprivateaes = secrets.randbelow(((self.p - 1) // 2)+1)
        self.dhprivatemac = secrets.randbelow(((self.p - 1) // 2)+1)
        self.clientrandom = secrets.token_bytes(32)
        self.counter = 1
        self.s = socket.socket()
        self.s.connect(('127.0.0.1', 5432))

    def countercheck(self, msg):
        if(int(msg[0]) <= self.counter):
            raise Exception("counter check failed or msg tampered with")
        self.counter = int(msg[0]) + 1

    def post_handshake(self): #takes in user input to interact with bank indefinitely
        print("ATM")
        print("Example login(atm will try to verify with your initalized user/pass): LOGIN")
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
            sendstr = self.user + '-'
            if inp.lower() == 'login':
                sendstr += inp.lower() + '-' + self.pw
            else:
                inp = inp.split(' ')
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
            sendstr = aes.encrypt(sendstr + "-" + hash.hmac(sendstr,self.mackey),self.aeskey)
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
            if hash.hmac(againsthash,self.mackey) != chkhash:
                print("bank return msg integrity compromised")
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
        print("Handshake info --> sending client random")
        self.s.send(str(self.clientrandom).encode('utf-8'))
        clirandplain = self.s.recv(99999).decode('utf-8')
        self.s.send("recieved plaintext signature".encode('utf-8'))
        clirandsign = self.s.recv(4096).decode('utf-8')
        if self.scheme == 'rsa':
            clirandsign = rsa.verify_signature(int(clirandsign),clirandplain,self.bankpubkey)
        else:
            clirandsign = clirandsign.strip("(").strip(")").split(",")
            clirandsign = [x.strip() for x in clirandsign] #take away tuple space or wierd stuff
            clirandsign = (int(clirandsign[0]), int(clirandsign[1]))
            clirandsign = elgamal.verify_signature(clirandsign,clirandplain,self.bankpubkey)

        if clirandsign:
            self.s.send("signature verify success".encode('utf-8'))
        else:
            self.s.send("signature verify failed".encode('utf-8'))
            self.s.close()
            raise Exception("signature verify failed")
        self.s.recv(4096) #formatting
        print("Handshake info --> bank signature verified, DH parameters recieved")
        self.s.send((str(pow(2, self.dhprivateaes, self.p)) + '-' + str(pow(2, self.dhprivatemac, self.p))).encode('utf-8'))
        clirandplain = clirandplain.split('-')
        self.aeskey = pow(int(clirandplain[-2]),self.dhprivateaes,self.p) % pow(2,256)
        self.mackey = pow(int(clirandplain[-1]),self.dhprivatemac,self.p) % pow(2,256)
        self.aeskey = str(hex(self.aeskey))[2:]
        self.mackey = str(hex(self.mackey))[2:]
        print("Handshake info --> atm calculated aes/mac keys from DH exchange")
        self.s.send((aes.encrypt("finished",self.aeskey)).encode('utf-8'))
        print(f"Handshake info --> ATM ready to go, bank replied {aes.decrypt(self.s.recv(1024).decode('utf-8'),self.aeskey)}")
        self.post_handshake()

if __name__ == "__main__":
    # atmtest = ATM("Alex","alexpassword",["rsa"])
    atmtest2 = ATM("Owen","owenpassword",["elgamal"])
    # print(atmtest2.pw)
    # print(atmtest.pw)
    # testatm = ATM("Owen","testpass", ['rsa'])
    atmtest2.starthandshake() 
