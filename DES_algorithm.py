
from typing import List

# Define all permutation and S-box tables (abbreviated here for clarity)
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

P = [16, 7, 20, 21,
     29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2, 8, 24, 14,
     32, 27, 3, 9,
     19, 13, 30, 6,
     22, 11, 4, 25]

S_BOXES = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]] * 8]

PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

def permute(block, table, n=64):
    result = 0
    for position in table:
        result = (result << 1) | ((block >> (n - position)) & 1)
    return result

def left_shift(bits, n):
    return ((bits << n) | (bits >> (28 - n))) & 0x0FFFFFFF

def generate_subkeys(key):
    key = permute(key, PC1)
    C, D = (key >> 28) & 0xFFFFFFF, key & 0xFFFFFFF
    subkeys = []
    for shift in SHIFTS:
        C, D = left_shift(C, shift), left_shift(D, shift)
        CD = (C << 28) | D
        subkeys.append(permute(CD, PC2, 56))
    return subkeys

def sbox_substitution(input_48bit):
    output = 0
    for i in range(8):
        chunk = (input_48bit >> (42 - i * 6)) & 0x3F
        row = ((chunk & 0x20) >> 4) | (chunk & 0x01)
        col = (chunk >> 1) & 0x0F
        output = (output << 4) | S_BOXES[i][row][col]
    return output

def des_function(block, subkeys, encrypt=True):
    block = permute(block, IP)
    L, R = (block >> 32) & 0xFFFFFFFF, block & 0xFFFFFFFF
    for i in range(16):
        k = subkeys[i] if encrypt else subkeys[15 - i]
        E_R = permute(R, E, 32)
        temp = sbox_substitution(E_R ^ k)
        temp = permute(temp, P, 32)
        L, R = R, L ^ temp
    pre_output = (R << 32) | L
    return permute(pre_output, FP)

def encrypt(plaintext, key):
    return des_function(plaintext, generate_subkeys(key), True)

def decrypt(ciphertext, key):
    return des_function(ciphertext, generate_subkeys(key), False)

# Example Usage
if __name__ == "__main__":
    plaintext = 0x0123456789ABCDEF
    key = 0x133457799BBCDFF1
    ciphertext = encrypt(plaintext, key)
    decrypted = decrypt(ciphertext, key)

    print(f"Plaintext: 0x{plaintext:016X}")
    print(f"Ciphertext: 0x{ciphertext:016X}")
    print(f"Decrypted: 0x{decrypted:016X}")
