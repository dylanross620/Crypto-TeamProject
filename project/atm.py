import json
import hash
import socket
import ast
import secrets
from PublicKey import rsa
from PublicKey import elgamal
from PrivateKey import aes

class ATM:
    def __init__(self, preflist = []):
        self.aeskey = None
        self.mackey = None
        self.p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
        if len(preflist) == 0:
            raise Exception("need to have preferences as the user to compare to server...")
        self.prefs = preflist
        self.counter = 1
        self.id_num = 0 # each atm would have it's own id number. We hard-coded it for this assignment for simplicity since there is only 1 atm
        self.s = socket.socket()
        self.s.connect(('127.0.0.1', 5432))

    def countercheck(self, msg):
        if(int(msg[0]) <= self.counter):
            raise Exception("counter check failed or msg tampered with")

        self.counter = int(msg[0]) + 1

    def post_handshake(self): #takes in user input to interact with bank indefinitely
        # Generate random starting counter value and send it to the bank
        self.counter = secrets.randbelow(pow(2, 2048))
        sendstr = str(self.counter)
        sendstr = aes.encrypt(str(self.counter) + "-" + hash.hmac(sendstr, self.mackey), self.aeskey)
        self.s.send(sendstr.encode('utf-8'))

        # Ensure bank correctly received our counter
        bankret = self.s.recv(99999).decode('utf-8')
        bankret = aes.decrypt(bankret, self.aeskey)
        bankret = bankret.split('-')
        try:
            self.countercheck(bankret)
        except Exception as e:
            print(str(e))
            self.s.close()
            return

        chkhash = bankret[-1]
        bankret.remove(chkhash)
        againsthash = '-'.join(bankret)
        bankret = bankret[1:]

        # Check if bank return message was modified
        if hash.hmac(againsthash, self.mackey) != chkhash:
            print("bank return msg integrity compromised")
            self.s.close()
            return

        print(f"Counter set, bank replied with '{bankret[0]}'")
        print("ATM")

        # User does not start logged in, so get their sign in credentials
        username = ""
        password = ""
        while True:
            print("Please log in")
            # Get credentials from user
            username = input("username: ")
            password = input("password: ")
            sendstr = username + '-' + hash.sha1(password)
            sendstr = str(self.counter) + '-' + sendstr

            # Send credentials to bank for verification
            sendstr = aes.encrypt(sendstr + "-" + hash.hmac(sendstr, self.mackey), self.aeskey)
            self.s.send(sendstr.encode('utf-8'))

            bankret = self.s.recv(99999).decode('utf-8')#parse this out
            bankret = aes.decrypt(bankret, self.aeskey)
            bankret = bankret.split('-')

            # Ensure not some sort of replay
            try:
                self.countercheck(bankret)
            except Exception as e:
                print(str(e))
                continue

            chkhash = bankret[-1]
            bankret.remove(chkhash)
            againsthash = '-'.join(bankret)
            bankret = bankret[1:]

            # Ensure message hasn't been tampered with
            if hash.hmac(againsthash, self.mackey) != chkhash:
                print("bank return msg integrity compromised")
                continue
            print(f"bank responded with '{bankret[2]}' to the login attempt")
            if bankret[2] == "login successful":
                break
        
        print("\nExample withdraw: 'withdraw [positive_int]'")
        print("Example deposit: 'deposit [positive_int]'")
        print("Example check: 'check balance'")
        print("To close ATM, type q")
        print("---------------------------------------------------")

        while True:
            inp = input("command: ")
            inp = inp.strip()
            if inp == 'q':
                break

            # Start packet with username
            sendstr = username + '-'
            inp = inp.split(' ')

            # All atm operations require 2 parameters, so check that first
            if len(inp) != 2:
                print("not a valid operation supported by bank")
                continue

            # Parse user input
            if inp[0].lower() == 'withdraw':
                sendstr += inp[0].lower()
            elif inp[0].lower() == 'deposit':
                sendstr += inp[0].lower()
            elif inp[0].lower() == 'check':
                sendstr += inp[0].lower()
            else:
                print("not a valid operation supported by bank")
                continue

            # Ensure number is positive, if it is a number
            if inp[1].isnumeric() and int(inp[1]) > 0:
                sendstr += '-' + inp[1]
            elif inp[0].lower() == 'check' and inp[1].lower() == 'balance':
                sendstr += '-' + inp[1]
            else:
                print("invalid money amount")
                continue

            sendstr = str(self.counter) + '-' + sendstr
            sendstr = aes.encrypt(sendstr + "-" + hash.hmac(sendstr, self.mackey), self.aeskey)
            self.s.send(sendstr.encode('utf-8'))

            # Get bank's response to our request
            bankret = self.s.recv(99999).decode('utf-8')#parse this out
            bankret = aes.decrypt(bankret, self.aeskey)
            bankret = bankret.split('-')

            # Ensure not replay
            try:
                self.countercheck(bankret)
            except Exception as e:
                print(str(e))
                continue

            chkhash = bankret[-1]
            bankret.remove(chkhash)
            againsthash = '-'.join(bankret)
            bankret = bankret[1:]

            # Check if message tampered with
            if hash.hmac(againsthash, self.mackey) != chkhash:
                print("bank return msg integrity compromised")
                continue

            print(f"bank responded with '{bankret[2]}' to the request, money in account: {bankret[1]}") 

        self.s.close()

    def starthandshake(self):
        # Send supported PKCs as a hello packet
        self.s.send((str(json.dumps(self.prefs))).encode('utf-8'))

        bankhello = self.s.recv(4096)
        scheme = bankhello.decode('utf-8')

        # Parse bank response to see which PKC to use
        if scheme == "rsa":
            keypairs = rsa.load_keys("local_storage/atm-rsa.txt", 4096)
            bankpubkey = rsa.load_public_key("local_storage/bank-rsa.txt") # simulates the bank's public keys being hardcoded into the atm. This way if we chose to reset the bank key, we don't have to update this
        else:
            keypairs = elgamal.load_keys("local_storage/atm-elgamal.txt", 2048)
            bankpubkey = elgamal.load_public_key("local_storage/bank-elgamal.txt") # see above
        pubkey = keypairs[0]
        privkey = keypairs[1]

        # Begin Diffie-Hellman
        print("Handshake info --> sending client random")

        # Generate random numbers and send to bank
        dhprivateaes = secrets.randbelow(((self.p - 1) // 2) + 1)
        dhprivatemac = secrets.randbelow(((self.p - 1) // 2) + 1)
        dh_message = str(pow(2, dhprivateaes, self.p)) + '-' + str(pow(2, dhprivatemac, self.p))
        self.s.send(dh_message.encode('utf-8'))

        # Get the bank's response
        clirandplain = self.s.recv(99999).decode('utf-8')
        self.s.send("recieved plaintext signature".encode('utf-8'))
        # Get the bank's signature to prove it sent the previous response
        clirandsign = self.s.recv(4096).decode('utf-8')

        # Verify the signature to ensure bank sent the message
        if scheme == 'rsa':
            clirandsign = rsa.verify_signature(int(clirandsign), clirandplain, bankpubkey)
        else:
            clirandsign = clirandsign.strip("(").strip(")").split(",")
            clirandsign = [x.strip() for x in clirandsign] #take away tuple space or wierd stuff
            clirandsign = (int(clirandsign[0]), int(clirandsign[1]))
            clirandsign = elgamal.verify_signature(clirandsign, clirandplain, bankpubkey)

        clirandplain = clirandplain.split('-')

        # Make sure the signature verified, and ensure our DH numbers were received by the bank properly
        if clirandsign and (clirandplain[0] + '-' + clirandplain[1]) == dh_message:
            self.s.send("signature verify success".encode('utf-8'))
        else:
            self.s.send("signature verify failed".encode('utf-8'))
            self.s.close()
            raise Exception("signature verify failed")

        self.s.recv(4096) #formatting

        # The bank got our DH numbers correctly and sent its own, so calculate keys
        print("Handshake info --> bank signature verified, DH parameters recieved")
        self.aeskey = pow(int(clirandplain[-2]), dhprivateaes, self.p) % pow(2,256)
        self.mackey = pow(int(clirandplain[-1]), dhprivatemac, self.p) % pow(2,256)
        self.aeskey = format(self.aeskey, '064x')
        self.mackey = format(self.mackey, '064x')
        print("Handshake info --> atm calculated aes/mac keys from DH exchange")

        # Tell bank that we have the keys and are ready to use AES
        self.s.send((aes.encrypt("finished",self.aeskey)).encode('utf-8'))
        print(f"Handshake info --> ATM ready to go, bank replied {aes.decrypt(self.s.recv(1024).decode('utf-8'),self.aeskey)}")

        # Prove to bank that we're actually an ATM
        # Tell the atm what our keys should be saved as
        self.s.send(aes.encrypt(f'atm{self.id_num}', self.aeskey).encode('utf-8'))

        # Receive a random number from the bank that is encrypted to our public key
        bank_challenge = aes.decrypt(self.s.recv(4096).decode('utf-8'), self.aeskey)

        # Decrypt the random number
        if scheme == 'rsa':
            response = rsa.decrypt(int(bank_challenge), privkey)
        else:
            bank_challenge = bank_challenge.strip('(').strip(')').split(',')
            bank_challenge = [int(c) for c in bank_challenge]
            response = elgamal.decrypt(bank_challenge, privkey)

        # Send back the hash of the random number and our encryption key to prove that we are the atm we said we are
        response = hash.sha1(response + self.aeskey)
        self.s.send(aes.encrypt(response, self.aeskey).encode('utf-8'))

        self.post_handshake()

if __name__ == "__main__":
    atmtest2 = ATM(["elgamal"])
    atmtest2.starthandshake() 
