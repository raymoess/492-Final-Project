import hashlib

def generate_hash(password):
    # Using SHA256 hashing algorithm
    hash_object = hashlib.sha256(password.encode())
    hex_dig = hash_object.hexdigest()
    return hex_dig[:32]  # Extracting the first 32 hexadecimal digits

password = "C$4922023"
hashed_password = generate_hash(password)
print("Hash of password:", hashed_password)
