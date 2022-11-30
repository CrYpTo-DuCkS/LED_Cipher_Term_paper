import numpy as np
from constants import *
from hashlib import pbkdf2_hmac
from hmac import new as new_hmac, compare_digest

def get_key_iv(password, salt, key_size=8, workload=100000):
    """
    Stretches the password and extracts an AES key, an HMAC key and an AES
    initialization vector.
    """
    assert (key_size == 8 or key_size == 16)
    stretched = pbkdf2_hmac('sha256', password, salt, workload, key_size + IV_SIZE + HMAC_KEY_SIZE)
    aes_key, stretched = stretched[:key_size], stretched[key_size:]
    hmac_key, stretched = stretched[:HMAC_KEY_SIZE], stretched[HMAC_KEY_SIZE:]
    iv = stretched[:IV_SIZE]
    return aes_key, hmac_key, iv

def bytes2matrix(text):
    """ Converts a 16-byte array into a 4x4 matrix.  """
    return [[(text[i]&0xf0)>>4, text[i]&0x0f, (text[i+1]&0xf0)>>4, text[i+1]&0x0f] for i in range(0, len(text), 2)]


def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array.  """
    return bytes([(matrix[i][j]<<4)+matrix[i][j+1] for i in range(4) for j in range(0,4,2)])

def xor_bytes(a, b):
    """ Returns a new byte array with the elements xor'ed. """
    return bytes(i^j for i, j in zip(a, b))

def inc_bytes(a):
    """ Returns a new byte array with the value increment by 1 """
    out = list(a)
    for i in reversed(range(len(out))):
        if out[i] == 0xFF:
            out[i] = 0
        else:
            out[i] += 1
            break
    return bytes(out)

def sub_cells(s):
        for i in range(4):
            for j in range(4):
                s[i][j] = S_BOX[s[i][j]]


def inv_sub_cells(s):
    for i in range(4):
        for j in range(4):
            s[i][j] = S_BOX_INV[s[i][j]]


def shift_rows(s):
    s[1][0], s[1][1], s[1][2], s[1][3] = s[1][1], s[1][2], s[1][3], s[1][0]
    s[2][0], s[2][1], s[2][2], s[2][3] = s[2][2], s[2][3], s[2][0], s[2][1]
    s[3][0], s[3][1], s[3][2], s[3][3] = s[3][3], s[3][0], s[3][1], s[3][2]


def inv_shift_rows(s):
    s[1][0], s[1][1], s[1][2], s[1][3] = s[1][3], s[1][0], s[1][1], s[1][2]
    s[2][0], s[2][1], s[2][2], s[2][3] = s[2][2], s[2][3], s[2][0], s[2][1]
    s[3][0], s[3][1], s[3][2], s[3][3] = s[3][1], s[3][2], s[3][3], s[3][0]

def add_round_key(s, k):
    for i in range(4):
        for j in range(4):
            s[i][j] ^= k[i][j]

def add_constants(s, key_size, rn):
    msb_k = (key_size & 0xF0) >> 4
    lsb_k = key_size & 0x0F
    msb_rc = (R_CON[rn] & 0x38) >> 3
    lsb_rc = R_CON[rn] & 0x07
    ac_mat = [[0^msb_k, msb_rc, 0, 0],
              [1^msb_k, lsb_rc, 0, 0],
              [2^lsb_k, msb_rc, 0, 0],
              [3^lsb_k, lsb_rc, 0, 0]]
    for i in range(4):
        for j in range(4):
            s[i][j] ^= ac_mat[i][j]

def mix_columns_serial(s):
    ans = np.matmul(GF16(MIX_MATRIX),GF16(s))
    for i in range(4):
        for j in range(4):
            s[i][j] = int(ans[i][j])

def inv_mix_columns_serial(s):
    ans = np.matmul(MIX_MATRIX_INV,GF16(s))
    for i in range(4):
        for j in range(4):
            s[i][j] = int(ans[i][j])

def pad(plaintext):
    """
    Pads the given plaintext with PKCS#7 padding to a multiple of 16 bytes.
    Note that if the plaintext size is a multiple of 16,
    a whole block will be added.
    """
    padding_len = 8 - (len(plaintext) % 8)
    padding = bytes([padding_len] * padding_len)
    return plaintext + padding

def unpad(plaintext):
    """
    Removes a PKCS#7 padding, returning the unpadded text and ensuring the
    padding was correct.
    """
    padding_len = plaintext[-1]
    assert padding_len > 0
    message, padding = plaintext[:-padding_len], plaintext[-padding_len:]
    assert all(p == padding_len for p in padding)
    return message

def split_blocks(message, block_size=8, require_padding=True):
        assert len(message) % block_size == 0 or not require_padding
        return [message[i:i+block_size] for i in range(0, len(message), block_size)]