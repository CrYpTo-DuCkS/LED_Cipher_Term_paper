import galois

S_BOX = {0:12, 1:5, 2:6, 3:11, 4:9, 5:0, 6:10, 7:13, 8:3, 9:14, 10:15, 11:8, 12:4, 13:7, 14:1, 15:2}
S_BOX_INV = {v: k for (k, v) in S_BOX.items()}
R_CON = [0x01,0x03,0x07,0x0F,0x1F,0x3E,0x3D,0x3B,0x37,0x2F,0x1E,0x3C,0x39,0x33,0x27,0x0E,0x1D,0x3A,0x35,0x2B,0x16,0x2C,0x18,0x30]
MIX_MATRIX = [[0x4, 0x1, 0x2, 0x2],
              [0x8, 0x6, 0x5, 0x6],
              [0xB, 0xE, 0XA, 0x9],
              [0x2, 0x2, 0xF, 0xB]]
HMAC_KEY_SIZE = 8
IV_SIZE = 8

SALT_SIZE = 16
HMAC_SIZE = 32

GF16 = galois.GF(2**4)