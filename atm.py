import json
import secrets
from PublicKey import rsa
from PublicKey import elgamal
class ATM:
    def __init__(self, username, password, preflist = []):
        self.user = username
        self.pw  = password
        # self.client_random = secrets.token_bytes(4096)
        # self.premaster = secrets.token_bytes(4096)
        if len(preflist) == 0:
            raise Exception("need to have preferences as the user to compare to server...")
        self.prefs = preflist
        self.scheme = None
        self.keypairs = None
        # self.bankrandom = None
    def withdraw_money(self):
        pass

    def deposit_money(self):
        pass

    def key_setup(self):
        if self.scheme == None:
            raise Exception("need to assign common scheme in atm!")
        if self.scheme == "rsa":
            self.keypairs = rsa.load_keys("local_storage/atm-rsa.txt", 4096)
        else:
            self.keypairs = elgamal.load_keys("local_storage/atm-elgamal.txt",4096)


if __name__ == "__main__":
    # atmtest = ATM()
    g = 6497955158
    m = 1
    n = 126869
    r = 35145
    print((g * (r**n) % (n**2)))