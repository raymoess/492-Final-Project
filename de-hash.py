import hashlib

def hash_password(password, salt=''):
    #Hashes a password with an optional salt.
    hash_obj = hashlib.sha256()
    hash_obj.update((password + salt).encode('utf-8'))
    return hash_obj.hexdigest()

def unhash_password(hashed_password, salt, password_list):
    #Attempts to reverse a hashed password using a list of possible passwords.
    for guess in password_list:
        if hash_password(guess, salt) == hashed_password:
            print("Password found:", guess)
            # Rehash without salt
            rehashed_password = hash_password(guess)
            print("Rehashed password without salt:", rehashed_password)
            return guess
    return None

# Example usage
hashed_password = "438d14dfa6aad391824ad82dc7265b0b291e9dcde07feda849ada0fd0e14dcf8"  # Example hashed password
salt = "728af67a0219a2785cf3ec298196d6b1"  # Example salt
password_list = ["password", "123456", "letmein", "qwerty", "C$4922024"]  # Example list of possible passwords to try

unhashed_password = unhash_password(hashed_password, salt, password_list)
if unhashed_password:
    print("The unhashed password is:", unhashed_password)
else:
    print("Password could not be unhashed.")