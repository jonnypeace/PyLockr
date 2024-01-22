#!/usr/bin/env python3

from cryptography.fernet import Fernet

def generate_fernet_key():
    # Generate a new Fernet key
    key = Fernet.generate_key()
    
    # Decode the key to convert from bytes to string
    decoded_key = key.decode()
    
    # Print the key and instructions for the user
    print("Generated Fernet Key:")
    print(decoded_key)
    print("\nPlease add the following line to your .bashrc file:")
    print(f"export FERNET_KEY='{decoded_key}'")
    print("\nAfter adding the key, remember to run 'source ~/.bashrc' or restart your terminal.")

if __name__ == "__main__":
    generate_fernet_key()
