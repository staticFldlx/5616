import struct
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
import time
import secrets
from dh import create_dh_key, calculate_dh_secret

BLOCK_SIZE = 16  # Define the size of the encryption block as 16 bytes (128 bits)

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.client = client
        self.server = server
        self.verbose = True # verbose
        self.shared_secret = None
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret

        # This can be broken into code run just on the server or just on the clientasdsad
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()  # 生成DH密钥对
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            print(my_public_key)
            # Receive their public key
            their_public_key = int(self.recv())
            print(their_public_key)
            # Obtain our shared secret
            self.shared_secret = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(self.shared_secret.hex()))

    def send(self, data):
        if self.shared_secret != None:
            # Add a time stamp
            timestamp = struct.pack("d", time.time())  # 使用double类型存储时间戳
            data = timestamp + data
            # Authenticate messages using HMAC
            mac = HMAC.new(self.shared_secret, digestmod=SHA256)
            mac.update(data)
            mac_digest = mac.digest()
            data += mac_digest

            # Encrypt messages in CBC mode using AES
            iv = secrets.token_bytes(BLOCK_SIZE)  # Generate a random IV
            cipher = AES.new(self.shared_secret, AES.MODE_CBC, iv)
            padded_data = self._pad_message(data)  # Fill the message
            encrypted_data = iv + cipher.encrypt(padded_data)  # Encrypted data
            print(cipher)
            print(padded_data)
            print(data)
            if self.verbose:
                print()
                print("Original message : {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length: {}".format(len(encrypted_data)))
                print()
        else:
            encrypted_data = data  # Send data directly without a shared key

        # The length of the encoded data is an unsigned two-byte integer ('H')
        pkt_len = struct.pack("H", len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize("H"))
        unpacked_contents = struct.unpack("H", pkt_len_packed)
        pkt_len = unpacked_contents[0]

        if self.shared_secret :
            # Receive encrypted data
            encrypted_data = self.conn.recv(pkt_len)
            iv = encrypted_data[:BLOCK_SIZE]  # Extract IV
            cipher = AES.new(self.shared_secret, AES.MODE_CBC, iv)
            decrypted_data = cipher.decrypt(encrypted_data[BLOCK_SIZE:])  # Decrypted data
            original_msg = self._unpad_message(decrypted_data)  # Remove fill

            # Authenticate MAC
            received_mac_digest = original_msg[-32:]  # MAC length is 32 bytes
            original_msg = original_msg[:-32]  # Remove MAC
            mac = HMAC.new(self.shared_secret, digestmod=SHA256)
            mac.update(original_msg)
            calculated_mac_digest = mac.digest()
            if received_mac_digest != calculated_mac_digest:
                raise ValueError("MAC verification failed!")

            # Extract timestamps
            timestamp = struct.unpack("d", original_msg[:8])[0]
            current_time = time.time()
            # Check for timestamp expiration (assuming message validity is 60 seconds)
            if abs(current_time - timestamp) > 60:
                raise ValueError("Timestamp verification failed!")

            original_msg = original_msg[8:]  # 去除时间戳

            if self.verbose:
                print()
                print("Receiving message of length: {}".format(len(encrypted_data)))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original message: {}".format(original_msg))
                print()
        else:
            original_msg = self.conn.recv(pkt_len)  # Receive data directly without a shared key

        return original_msg

    def close(self):
        self.conn.close()

    def _pad_message(self, message: bytes) -> bytes:
        # Padding the message so that its length is a multiple of the block size
        pad_length = BLOCK_SIZE - len(message) % BLOCK_SIZE
        padding = bytes([pad_length] * pad_length)
        return message + padding

    def _unpad_message(self, padded_message: bytes) -> bytes:
        # Remove padding from messages
        pad_length = padded_message[-1]
        return padded_message[:-pad_length]
