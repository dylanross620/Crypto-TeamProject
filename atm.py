import json
import secrets
from PublicKey import rsa
from PublicKey import elgamal
import hash

class ATM:
    def __init__(self, username, password, preflist = []):
        self.user = username
        self.pw  = hash.sha256(password)
        self.aeskey = str(secrets.token_bytes(256))
        if len(preflist) == 0:
            raise Exception("need to have preferences as the user to compare to server...")
        self.prefs = preflist
        self.scheme = None
        self.pubkey = None
        self.privkey = None
        self.bankpubkey = None

    def withdraw_money(self):
        pass

    def deposit_money(self):
        pass

    def key_setup(self, bpubkey):
        if self.scheme == None:
            raise Exception("need to assign common scheme in atm!")
        keypairs = None
        if self.scheme == "rsa":
            keypairs = rsa.load_keys("local_storage/atm-rsa.txt", 4096)
        else:
            keypairs = elgamal.load_keys("local_storage/atm-elgamal.txt",4096)
        self.pubkey = keypairs[0]
        self.privkey = keypairs[1]
        self.bankpubkey = bpubkey
        ekey = None
        if self.scheme == "rsa":
            ekey = rsa.encrypt(self.aeskey + hash.sha256(self.aeskey),self.bankpubkey)
        else:
            ekey = elgamal.encrypt(self.aeskey + hash.sha256(self.aeskey), self.bankpubkey)

        return ekey #this is being sent across the network, could intercept here before bank recieves...

    def send_user():
        return self.user
    
    def send_pass():
        return self.pw
if __name__ == "__main__":
    atmtest = ATM("Alex","alexpassword",["rsa"])
    atmtest2 = ATM("Owen","owenpassword",["elgamal"])