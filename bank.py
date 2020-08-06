import json

class Bank:
    def __init__(self):
        self.usertopass = json.loads(open("local_storage/usertohashpass.txt", "r").read()) #returns dict structured (user:hashpass)
        self.usertomoney = json.loads(open("local_storage/usertomoney.txt", "r").read()) #returns dict structured (user:plaintext_money)
        self.methods = ['rsa', 'elgamal'] #in order of preference

    def addhashedpassword(username: str, password: str):
        self.usertopass[username] = password
        open("local_storage/usertohashpass.txt", "w+").write(json.dumps(self.usertopass))

    def addusertomoney(username: str, amount: str): #adds info to runtime dict and dumps to file
        self.usertomoney[username] = amount
        open("local_storage/usertomoney.txt", "w+").write(json.dumps(self.usertomoney))

if __name__ == "__main__":
    testbank = Bank()
    print(testbank.usertopass)
    print(testbank.usertomoney)
    for k in testbank.usertomoney.keys():
        print("USER TO MONEY --> %s: %s" % (k, testbank.usertomoney[k]))
    for k in testbank.usertopass.keys():
        print("USER TO PASS --> %s: %s" % (k, testbank.usertopass[k]))
