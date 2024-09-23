import hashlib
import secrets
import string
import time
import pyotp #one time password library
import qrcode #qrcode librayr
import json 
import os

#strong authentication protocol
class StrongAuthenticator:
    def __init__(self, user_file):
        self.user_file = user_file
        self.failed_login_attempts = {}  #initialize failed login attempts
        self.load_users()

    def load_users(self):
        if os.path.exists(self.user_file):
            with open(self.user_file, 'r') as file: #opening and reading json file
                self.users = json.load(file)
        else:
            self.users = {}

    def save_users(self):
        with open(self.user_file, 'w') as file: #opening and writing to json file
            json.dump(self.users, file)

    def register(self, username, password):  #method for registering new user
        if username in self.users:  #checking if the username already exists
            print("User already exists. Please choose a different username.")
            return False

        if not self._validate_password(password):  #making sure the password meets the parameters
            print("Password must be at least 8 characters long and contain at least one symbol.")
            return False

        salt = secrets.token_hex(16)  #generating a random salt
        otp_secret = self.generate_otp_secret(username)  # Generate OTP secret key
        hashed_password = self._hash_password(password, salt)  # hashing the password w/ the salt
        self.users[username] = {'password': hashed_password, 'salt': salt, 'otp_secret': otp_secret}  # storing the hashed password, salt, and otp_secret and assigning it to the username
        self.save_users()
        self.generate_qr_code(username, otp_secret)  #generate and save QR code
        print("User registered successfully.")
        return True

    def login(self, username, password):  # authenticating user
        if username not in self.users:  # checking if the username exists
            print("Invalid username or password.\n")
            return False

        locked_info = self._is_account_locked(username)  # checking if an account is locked due to multiple failed attempts
        if locked_info:
            remaining_time = round(60 - (time.time() - locked_info['last_attempt_time']))
            # calculating the remaining time before a user is able to try signing in again after being locked out
            print(f"Account locked due to multiple failed login attempts. Please try again later. Time remaining: {remaining_time} seconds.")
            return False

        hashed_password = self._hash_password(password, self.users[username]['salt'])  # check if the hashed password matches the stored password

        if self.users[username]['password'] == hashed_password:
            #if the password is correct, generate and verify the 2FA code
            totp = pyotp.TOTP(self.users[username]['otp_secret'])
            print("Scan this QR code with your Authenticator app:")
            uri = totp.provisioning_uri(username, issuer_name="YourApp")
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(uri)
            qr.make(fit=True)
            img = qr.make_image(fill='black', back_color='white')
            img.save("totp.png")
            entered_2fa_code = input("Enter 2FA code from your Authenticator app: ")

            if totp.verify(entered_2fa_code): #if the verification code and password match the user info, login
                print("Login successful.")
                return True
            else:
                print("Invalid two-factor authentication code.") #if the verification code is incorrect, fail
                return False
        else:
            self._increment_failed_login_attempts(username)  # incrementing failed login attempts
            attempts_left = 3 - self.failed_login_attempts.get(username, {'attempts': 0})['attempts']
            if attempts_left > 0:
                print(f"Invalid username or password. You have {attempts_left} attempts left before your account is locked.") #printing the number of attempts a user has to login after failing
            else:
                print("Invalid username or password. Account locked.") #locks after 3 failed attempts
                print("Exiting...")
            return False

    def _hash_password(self, password, salt):  #hashing the password with salt using SHA256 algo
        return hashlib.sha256((password + salt).encode()).hexdigest()

    def _is_account_locked(self, username):  #checking if the account is locked
        if username in self.failed_login_attempts:
            attempts = self.failed_login_attempts[username]['attempts']
            last_attempt_time = self.failed_login_attempts[username]['last_attempt_time']
            if attempts >= 3 and time.time() - last_attempt_time < 60:
                return {'attempts': attempts, 'last_attempt_time': last_attempt_time}
            elif time.time() - last_attempt_time >= 60:
                self.failed_login_attempts.pop(username)  #reset attempts after 60 seconds
        return False

    def _increment_failed_login_attempts(self, username):  #increment the number of failed login attempts
        if username in self.failed_login_attempts:
            self.failed_login_attempts[username]['attempts'] += 1  # update the amount of attempts remaining
            self.failed_login_attempts[username]['last_attempt_time'] = time.time()
        else:
            self.failed_login_attempts[username] = {'attempts': 1, 'last_attempt_time': time.time()}

    def _validate_password(self, password):  #making sure the password is 8 characters long
        if len(password) < 8:
            return False
        if not any(char in string.punctuation for char in password):  #making sure the password contains at least one symbol
            return False
        return True

    def generate_otp_secret(self, username):
        #generate a random secret key for TOTP
        return pyotp.random_base32()

    def generate_qr_code(self, username, otp_secret):
        #generate QR code for OTP provisioning URI and save it with username as filename
        totp = pyotp.TOTP(otp_secret)
        uri = totp.provisioning_uri(username, issuer_name="YourApp")
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill='black', back_color='white')
        img.save(f"{username}_qr.png")


#specify the file path where user data will be saved
user_file_path = "users.json"

#creating an instance of the StrongAuthenticator class for authentication purposes
strong_auth = StrongAuthenticator(user_file_path)

#asking the user to register
def register_user():
    while True:
        username = input("Enter username: ")
        password = input("Enter password: ")
        if strong_auth.register(username, password):
            break

#asking the user to login based on registration
def login_user():
    while True:
        username = input("Enter username: ")
        password = input("Enter password: ")
        if strong_auth.login(username, password):
            break

#display menu options
while True:
    print("\n1. Register\n2. Login\n3. Exit")
    choice = input("Enter your choice: ")

    if choice == "1":
        register_user()
    elif choice == "2":
        login_user()
    elif choice == "3":
        print("Exiting...")
        break
    else:
        print("Invalid choice. Please try again.")
