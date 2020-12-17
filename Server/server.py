"""
    server.py - host an SSL server that checks passwords

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 140
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:
    Spencer Koller
    Taylor Sittersen


"""

import socket
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import AES
from Crypto.PublicKey import  RSA
import hashlib
host = "localhost"
port = 10001

# A helper function. It may come in handy when performing symmetric encryption
def pad_message(message):
    return message + " " * ((16 - len(message)) % 16)


# Write a function that decrypts a message using the server's private key
def decrypt_key(session_key):
    return PKCS1_v1_5.new(RSA.importKey(open('private_key.pem', 'r').read())).decrypt(session_key, "error")
# Write a function that decrypts a message using the session key
def decrypt_message(client_message, session_key):
    return AES.new(session_key).decrypt(client_message)   

# Encrypt a message using the session key
def encrypt_message(message, session_key):
    # use pad_message to apply padding for symmetric encryption
    # similar to decrypt_mesage
    return AES.new(session_key).encrypt(pad_message(message))

# Sends message to client
def send_message(connection, data):
    if not data:
        print("Can't send empty string")
        return
    if type(data) != bytes:
        data = data.encode()
    connection.sendall(data)

def receive_message(connection):
    return connection.recv(1024)

# A function that reads in the password file, salts and hashes the password, and
# checks the stored hash of the password to see if they are equal. It returns
# True if they are and False if they aren't. The delimiters are newlines and tabs
def verify_hash(user, password):
    try:
        reader = open("passfile.txt", 'r')
        for line in reader.read().split('\n'):
            line = line.split("\t")
            if line[0] == user:
                # had trouble with string to byte conversion, using hashlib.sha512 instead
                hashed_password = hashlib.sha512((password + line[1]).encode()).hexdigest()
                return hashed_password == line[2]
        reader.close()
    except FileNotFoundError:
        return False
    return False


def main():
    # Set up network connection listener
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    print('starting up on {} port {}'.format(*server_address))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(server_address)
    sock.listen(1)

    try:
        while True:
            # Wait for a connection
            print('waiting for a connection')
            connection, client_address = sock.accept()
            try:
                print('connection from', client_address)

                # Receive encrypted key from client
                encrypted_key = receive_message(connection)

                # Send okay back to client
                send_message(connection, "okay")

                # Decrypt key from client
                plaintext_key = decrypt_key(encrypted_key)

                # Receive encrypted message from client
                ciphertext_message = receive_message(connection)

                # Decrypt message from client
                plaintext_message = decrypt_message(ciphertext_message, plaintext_key)
                # TODO: Split response from user into the username and password
                user, password = plaintext_message.split()
                verify = verify_hash(user, password)
                if (verify == false):
                    print("Password or username incorrect")
                else:
                    print("User sucessfuly authenticated!")
                # TODO: Encrypt response to client
                ciphertext_response = encrypt_message(plaintext_response, plaintext_key)
                # Send encrypted response
                send_message(connection, ciphertext_response)
            finally:
                # Clean up the connection
                connection.close()
    finally:
        sock.close()


if __name__ in "__main__":
    main()
