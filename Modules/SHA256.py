import hashlib

def HashPassword(Password, UserID):
    Salt = hashlib.sha256(UserID.encode('utf-8')).hexdigest()
    Data = Password.encode('utf-8') + Salt.encode('utf-8')
    Hash = hashlib.sha256(Data).hexdigest()
    return Hash

def CheckPassword(Password, StoredHash, UserID):
    Salt = hashlib.sha256(UserID.encode('utf-8')).hexdigest()
    Data = Password.encode('utf-8') + Salt.encode('utf-8')
    HashGen = hashlib.sha256(Data).hexdigest()
    return HashGen == StoredHash