import secrets

# Generate a secure 32-byte key (256-bit)
secret_key = secrets.token_hex(32)

print("Generated Secret Key:")
print(secret_key)



