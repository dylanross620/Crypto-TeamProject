import json
from PublicKey import rsa
class Bank:
    def __init__(self, atmpreflist = []):
        self.usertopass = json.loads(open("local_storage/usertohashpass.txt", "r").read()) #returns dict structured (user:hashpass)
        self.usertomoney = json.loads(open("local_storage/usertomoney.txt", "r").read()) #returns dict structured (user:plaintext_money)
        self.methods = ['rsa', 'elgamal'] #in order of preference
        atmpreflist = [x.lower() for x in atmpreflist]
        self.common = list(set(self.methods) & set(atmpreflist))
        if len(self.common) == 0:
            raise Exception("no common methods between atm/bank")
        else:
            self.common = self.common[0]
        self.read = rsa.load_keys("bank-" + self.common + ".txt", 128)
    def addhashedpassword(username: str, password: str):
        self.usertopass[username] = password
        open("local_storage/usertohashpass.txt", "w+").write(json.dumps(self.usertopass))

    def addusertomoney(username: str, amount: str): #adds info to runtime dict and dumps to file
        self.usertomoney[username] = amount
        open("local_storage/usertomoney.txt", "w+").write(json.dumps(self.usertomoney))

if __name__ == "__main__":
    testbank = Bank(["rsa"])
    print(testbank.usertopass)
    print(testbank.usertomoney)
    for k in testbank.usertomoney.keys():
        print("USER TO MONEY --> %s: %s" % (k, testbank.usertomoney[k]))
    for k in testbank.usertopass.keys():
        print("USER TO PASS --> %s: %s" % (k, testbank.usertopass[k]))
    print(testbank.common)
    print(self.read)