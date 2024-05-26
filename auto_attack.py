#!/usr/bin/python3
import socket
import sys
from binascii import hexlify, unhexlify

# XOR two bytearrays
def xor(first, second):
   return bytearray(x^y for x,y in zip(first, second))

class PaddingOracle:

    def __init__(self, host, port) -> None:
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((host, port))

        ciphertext = self.s.recv(4096).decode().strip()
        self.ctext = unhexlify(ciphertext)

    def decrypt(self, ctext: bytes) -> None:
        self._send(hexlify(ctext))
        return self._recv()

    def _recv(self):
        resp = self.s.recv(4096).decode().strip()
        return resp 

    def _send(self, hexstr: bytes):
        self.s.send(hexstr + b'\n')

    def __del__(self):
        self.s.close()

def oracle_attack(oracle, IV, C1, C2, op):

    C = bytearray(16)
    D = bytearray(16)
    K = 0x01

    # AES-CBC encryption - 16 bytes block
    for i in range(16):

        # Set the padding bytes in C' depending on the position
        for j in range(K-1):
            C[15-j] = D[15-j] ^ K


        for j in range(256):

            # Iterate over the desired byte of C'
            C[16 - K] = j

            # Send the input to the oracle
            if op == "D1":
                status = oracle.decrypt(C + C1)

            elif op == "D2":
                status = oracle.decrypt(IV + C + C2)

            # Check if the padding is valid
            if status == "Valid":
                print("Discovered bit at position", 15-i, "\t", hex(j ^ K))
                D[15 - i] = j ^ K

        K += 1

    return D


if __name__ == "__main__":

    oracle = PaddingOracle('10.9.0.80', int(sys.argv[1]))

    # Get the IV + Ciphertext from the oracle
    iv_and_ctext = bytearray(oracle.ctext)
    IV    = iv_and_ctext[00:16]
    C1    = iv_and_ctext[16:32]  # 1st block of ciphertext
    C2    = iv_and_ctext[32:48]  # 2nd block of ciphertext

    print("\nIV:  " + IV.hex())
    print("C1:  " + C1.hex())
    print("C2:  " + C2.hex() + "\n")

    D1 = oracle_attack(oracle, IV, C1, C2, "D1")
    D2 = oracle_attack(oracle, IV, C1, C2, "D2")
    Plain_text1 = xor(IV, D1)
    Plain_text2 = xor(C1, D2)

    print("\nPlain text:")
    print(Plain_text1.hex())
    print(Plain_text2.hex())
    print("\n")

