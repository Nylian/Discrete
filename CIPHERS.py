import os
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def Caesar_cipher():
    os.system("cls")
    plain_text = input("Input Plain text: ")
    key = int(input("Input key: "))
    
    alphabet = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", 
                "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"]
    
    caesar_cipher_text = ""
    for char in plain_text:
        upper_char = char.upper()
        if upper_char in alphabet:
            index = alphabet.index(upper_char)
            shifted_index = (index + key) % 26
            caesar_cipher_text += alphabet[shifted_index]
        else:
            caesar_cipher_text += char  
            
    os.system("cls")
    print("Original text: ", plain_text)
    print("Cipher Text: ", caesar_cipher_text)

def Rail_fence():
    os.system("cls")
    plain_text = input("Input Plain text: ")
    key = int(input("Input key: "))
    
    rails = [''] * key  # Initialize rail levels
    row, direction = 0, 1

    for char in plain_text:
        rails[row] += char
        row += direction
        if row == 0 or row == key - 1:
            direction *= -1  # Switch direction

    print("Original text:", plain_text)
    print("Cipher Text:", ''.join(rails))
    

def Vigenere_cipher():
    os.system("cls")

    plain_text = input("Input Plain text: ")
    key = input("Input key (word): ").upper()

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    cipher_text = ""
    
    key_index = 0
    for char in plain_text:
        upper_char = char.upper()
        if upper_char in alphabet:
            shift = alphabet.index(key[key_index % len(key)])
            index = (alphabet.index(upper_char) + shift) % 26
            cipher_text += alphabet[index]
            key_index += 1  # Move to the next letter in the key
        else:
            cipher_text += char

    os.system("cls")
    print("Original text:", plain_text)
    print("Cipher Text:", cipher_text)
    
def Playfair_cipher():
    os.system("cls")
    plain_text = input("Input Plain text: ").upper().replace("J", "I")
    key = input("Input key (word): ").upper().replace("J", "I")

    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    matrix_key = ""
    for char in key:
        if char in alphabet and char not in matrix_key:
            matrix_key += char
    for char in alphabet:
        if char not in matrix_key:
            matrix_key += char

    matrix = [list(matrix_key[i*5:(i+1)*5]) for i in range(5)]

    # Prepare plaintext digraphs
    prepared = ""
    i = 0
    while i < len(plain_text):
        a = plain_text[i]
        if a not in alphabet:
            i += 1
            continue
        if i + 1 < len(plain_text):
            b = plain_text[i+1]
            if b not in alphabet:
                prepared += a
                i += 1
                continue
            if a == b:
                prepared += a + "X"
                i += 1
            else:
                prepared += a + b
                i += 2
        else:
            prepared += a + "X"
            i += 1

    # Encrypt digraphs
    cipher_text = ""
    for i in range(0, len(prepared), 2):
        a = prepared[i]
        b = prepared[i+1]
        row1 = col1 = row2 = col2 = 0
        for row in range(5):
            for col in range(5):
                if matrix[row][col] == a:
                    row1, col1 = row, col
                if matrix[row][col] == b:
                    row2, col2 = row, col
        if row1 == row2:
            cipher_text += matrix[row1][(col1+1)%5]
            cipher_text += matrix[row2][(col2+1)%5]
        elif col1 == col2:
            cipher_text += matrix[(row1+1)%5][col1]
            cipher_text += matrix[(row2+1)%5][col2]
        else:
            cipher_text += matrix[row1][col2]
            cipher_text += matrix[row2][col1]

    os.system("cls")
    print("Original text:", plain_text)
    print("Cipher Text:", cipher_text)
    
    
def Vernam_cipher():
    os.system("cls")
    plain_text = input("Input Plain text: ")
    key = input("Input key (same length as plain text): ")

    if len(plain_text) != len(key):
        print("Error: Key must be the same length as the plain text.")
        return

    # Encrypt: XOR each byte, then encode as base64 for printable output
    cipher_bytes = bytes([(ord(plain_text[i]) ^ ord(key[i])) for i in range(len(plain_text))])
    cipher_b64 = base64.b64encode(cipher_bytes).decode()

    os.system("cls")
    print("Original text:", plain_text)
    print("Cipher Text (base64):", cipher_b64)

    # Optional: Demonstrate decryption from base64
    decoded_bytes = base64.b64decode(cipher_b64)
    decrypted_bytes = bytes([(decoded_bytes[i] ^ ord(key[i])) for i in range(len(decoded_bytes))])
    try:
        decrypted_text = decrypted_bytes.decode()
    except UnicodeDecodeError:
        decrypted_text = decrypted_bytes.decode(errors='replace')
    print("Decrypted:", decrypted_text)
    
def One_Time_Pad_cipher():
    os.system("cls")
    plain_text = input("Input Plain text: ")
    key = input("Input key (same length as plain text): ")

    if len(plain_text) != len(key):
        print("Error: Key must be the same length as the plain text.")
        return

    cipher_text = ""
    for i in range(len(plain_text)):
        cipher_char = chr((ord(plain_text[i]) + ord(key[i])) % 256)
        cipher_text += cipher_char

    os.system("cls")
    print("Original text:", plain_text)
    print("Cipher Text:", cipher_text)
    
def Hill_cipher():
    os.system("cls")
    plain_text = input("Input Plain text: ").upper().replace(" ", "")
    print("Enter 4 numbers for the 2x2 key matrix (row-wise, separated by spaces):")
    key_input = input("Key: ")
    key_nums = key_input.strip().split()
    if len(key_nums) != 4 or not all(num.isdigit() for num in key_nums):
        print("Invalid key. Enter 4 numbers separated by spaces.")
        return
    key_matrix = [ [int(key_nums[0]), int(key_nums[1])],
                   [int(key_nums[2]), int(key_nums[3])] ]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    # Pad plaintext if needed
    if len(plain_text) % 2 != 0:
        plain_text += "X"
    cipher_text = ""
    for i in range(0, len(plain_text), 2):
        pair = [alphabet.index(plain_text[i]), alphabet.index(plain_text[i+1])]
        c1 = (key_matrix[0][0]*pair[0] + key_matrix[0][1]*pair[1]) % 26
        c2 = (key_matrix[1][0]*pair[0] + key_matrix[1][1]*pair[1]) % 26
        cipher_text += alphabet[c1] + alphabet[c2]
    os.system("cls")
    print("Original text:", plain_text)
    print("Cipher Text:", cipher_text)
    
def Columnar_cipher():
    os.system("cls")
    plain_text = input("Input Plain text: ")
    key = input("Input key (word): ").upper()

    # Create a list of columns based on the key
    columns = [''] * len(key)
    for i, char in enumerate(plain_text):
        columns[i % len(key)] += char

    # Sort the key to determine the order of columns
    sorted_key = sorted((char, i) for i, char in enumerate(key))
    
    # Create cipher text by reading columns in sorted order
    cipher_text = ''.join(columns[i] for _, i in sorted_key)

    os.system("cls")
    print("Original text:", plain_text)
    print("Cipher Text:", cipher_text)
    
def AES_cipher():
    os.system("cls")
    print("AES Cipher (ECB mode, 16-byte key)")
    plain_text = input("Input Plain text: ")
    key = input("Input key (16 characters): ")
    if len(key) != 16:
        print("Key must be exactly 16 characters (128 bits) for AES-128.")
        return
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    padded_text = pad(plain_text.encode(), AES.block_size)
    encrypted_bytes = cipher.encrypt(padded_text)
    encrypted_b64 = base64.b64encode(encrypted_bytes).decode()
    print("Encrypted (base64):", encrypted_b64)
    # Decrypt demo
    decrypted_bytes = cipher.decrypt(base64.b64decode(encrypted_b64))
    decrypted_text = unpad(decrypted_bytes, AES.block_size).decode()
    print("Decrypted:", decrypted_text)

def DES_cipher():
    os.system("cls")
    print("DES Cipher (ECB mode, 8-byte key)")
    plain_text = input("Input Plain text: ")
    key = input("Input key (8 characters): ")
    if len(key) != 8:
        print("Key must be exactly 8 characters (64 bits) for DES.")
        return
    cipher = DES.new(key.encode(), DES.MODE_ECB)
    padded_text = pad(plain_text.encode(), DES.block_size)
    encrypted_bytes = cipher.encrypt(padded_text)
    encrypted_b64 = base64.b64encode(encrypted_bytes).decode()
    print("Encrypted (base64):", encrypted_b64)
    # Decrypt demo
    decrypted_bytes = cipher.decrypt(base64.b64decode(encrypted_b64))
    decrypted_text = unpad(decrypted_bytes, DES.block_size).decode()
    print("Decrypted:", decrypted_text)

def SDES_cipher():
    os.system("cls")
    print("SDES Cipher (Simplified DES, 8-bit blocks, 10-bit key)")
    def permute(bits, table):
        return ''.join(bits[i-1] for i in table)
    def left_shift(bits, n):
        return bits[n:] + bits[:n]
    def xor(bits1, bits2):
        return ''.join('0' if b1 == b2 else '1' for b1, b2 in zip(bits1, bits2))
    def sbox(input_bits, sbox):
        row = int(input_bits[0] + input_bits[3], 2)
        col = int(input_bits[1] + input_bits[2], 2)
        return format(sbox[row][col], '02b')
    # Permutation tables
    P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    P8 = [6, 3, 7, 4, 8, 5, 10, 9]
    IP = [2, 6, 3, 1, 4, 8, 5, 7]
    IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]
    EP = [4, 1, 2, 3, 2, 3, 4, 1]
    P4 = [2, 4, 3, 1]
    S0 = [[1,0,3,2],[3,2,1,0],[0,2,1,3],[3,1,3,2]]
    S1 = [[0,1,2,3],[2,0,1,3],[3,0,1,0],[2,1,0,3]]
    # Key generation
    key = input("Enter 10-bit key (e.g. 1010000010): ")
    if len(key) != 10 or any(c not in '01' for c in key):
        print("Key must be 10 bits (0/1 only)")
        return
    k1 = permute(left_shift(left_shift(permute(key, P10)[:5], 1) + left_shift(permute(key, P10)[5:], 1), 0), P8)
    k2 = permute(left_shift(left_shift(permute(key, P10)[:5], 3) + left_shift(permute(key, P10)[5:], 3), 0), P8)
    # Encrypt/decrypt
    def f_k(bits, subkey):
        L, R = bits[:4], bits[4:]
        temp = permute(R, EP)
        temp = xor(temp, subkey)
        left, right = temp[:4], temp[4:]
        sbox_out = sbox(left, S0) + sbox(right, S1)
        sbox_out = permute(sbox_out, P4)
        return xor(L, sbox_out) + R
    def sdes_encrypt(plain, k1, k2):
        bits = permute(plain, IP)
        bits = f_k(bits, k1)
        bits = bits[4:] + bits[:4]
        bits = f_k(bits, k2)
        return permute(bits, IP_inv)
    def sdes_decrypt(cipher, k1, k2):
        bits = permute(cipher, IP)
        bits = f_k(bits, k2)
        bits = bits[4:] + bits[:4]
        bits = f_k(bits, k1)
        return permute(bits, IP_inv)
    plain = input("Enter 8-bit plaintext (e.g. 10101011): ")
    if len(plain) != 8 or any(c not in '01' for c in plain):
        print("Plaintext must be 8 bits (0/1 only)")
        return
    cipher = sdes_encrypt(plain, k1, k2)
    print("Encrypted (ciphertext):", cipher)
    decrypted = sdes_decrypt(cipher, k1, k2)
    print("Decrypted (plaintext):", decrypted)
    
def RSA_encryption():
    os.system("cls")
    print("RSA Encryption/Decryption Demo")
    # Generate RSA key pair
    key = RSA.generate(2048)
    public_key = key.publickey()
    cipher = PKCS1_OAEP.new(public_key)
    plain_text = input("Input Plain text: ").encode()
    encrypted = cipher.encrypt(plain_text)
    print("Encrypted (base64):", base64.b64encode(encrypted).decode())
    # Decrypt
    cipher_dec = PKCS1_OAEP.new(key)
    decrypted = cipher_dec.decrypt(encrypted)
    print("Decrypted:", decrypted.decode())


ciphers = [ "Caesar Cipher",
            "Vigenère Cipher",
            "Playfair Cipher",
            "Vernam Cipher",
            "One Time Pad Cipher",
            "Hill Cipher",
            "Rail Fence Cipher",
            "Columnar Cipher",
            "AES Cipher",
            "DES Cipher",
            "SDES Cipher",
            "RSA Encryption"]
running = True
while(running):
    os.system("cls")
    print("Ciphers")
    i = 1
    for cipher in ciphers:
        print(f"{i}.", cipher)
        i = i + 1 
        
    cipher = input("Choose Cipher: " )
    match cipher:
        case "1":
            Caesar_cipher()
        case "2":
            Vigenere_cipher()
        case "3":
            Playfair_cipher()
        case "4":
            Vernam_cipher()
        case "5":
            One_Time_Pad_cipher()
        case "6":
            Hill_cipher()
        case "7":
            Rail_fence()
        case "8":
            Columnar_cipher()
        case "9":
            AES_cipher()
        case "10":
            DES_cipher()
        case "11":
            SDES_cipher()
        case "12":
            RSA_encryption()

    restart = input("\nStart again? [y/n]: ")
    if restart == "n" or restart == "N":
        running = False