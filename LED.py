from utils import *
from copy import deepcopy
import os


class LED:
    rounds_by_key_size = {8: 8, 16: 12}
    def __init__(self, master_key):
        self.__master_key = master_key
        self.n_rounds = LED.rounds_by_key_size[len(master_key)]
        self.key_schedule()
        self.modes_dict = {'ebc':(self.encrypt_ebc,self.decrypt_ebc),
                           'cbc':(self.encrypt_cbc,self.decrypt_cbc),
                           'pcbc':(self.encrypt_pcbc,self.decrypt_pcbc),
                           'cfb':(self.encrypt_cfb,self.decrypt_cfb),
                           'ofb':(self.encrypt_ofb,self.decrypt_ofb),
                           'ctr':(self.encrypt_ctr,self.decrypt_ctr)}

    def key_schedule(self):
        self.__subkeys = []
        if len(self.__master_key) == 8:
            self.__subkeys.append(bytes2matrix(self.__master_key))
        else:
            self.__subkeys.append(bytes2matrix(self.__master_key[0:8]))
            self.__subkeys.append(bytes2matrix(self.__master_key[8:16]))
        # print(self.__subkeys)

    def encrypt_block(self, plaintext):
        """
        Encrypts a single block of 16 byte long plaintext.
        """
        assert len(plaintext) == 8

        plain_state = bytes2matrix(plaintext)
        # state_after_every_round = []
        # state_after_every_round.append(deepcopy(plain_state))

        for i in range(self.n_rounds-1):
            add_round_key(plain_state, self.__subkeys[min(i%2,len(self.__subkeys)-1)])
            # state_after_every_round.append(deepcopy(plain_state))
            add_constants(plain_state, len(self.__master_key), i)
            # state_after_every_round.append(deepcopy(plain_state))
            sub_cells(plain_state)
            # state_after_every_round.append(deepcopy(plain_state))
            shift_rows(plain_state)
            # state_after_every_round.append(deepcopy(plain_state))
            mix_columns_serial(plain_state)
            # state_after_every_round.append(deepcopy(plain_state))
        
        add_round_key(plain_state, self.__subkeys[min((self.n_rounds-1)%2,len(self.__subkeys)-1)])
        # state_after_every_round.append(deepcopy(plain_state))

        return matrix2bytes(plain_state)

    def decrypt_block(self, ciphertext):
        """
        Decrypts a single block of 16 byte long ciphertext.
        """
        assert len(ciphertext) == 8

        cipher_state = bytes2matrix(ciphertext)

        add_round_key(cipher_state, self.__subkeys[min((self.n_rounds-1)%2,len(self.__subkeys)-1)])

        for i in range(self.n_rounds - 2, -1, -1):
            inv_mix_columns_serial(cipher_state)
            inv_shift_rows(cipher_state)
            inv_sub_cells(cipher_state)
            add_constants(cipher_state, len(self.__master_key), i)
            add_round_key(cipher_state, self.__subkeys[min(i%2,len(self.__subkeys)-1)])


        return matrix2bytes(cipher_state)

    def encrypt_ebc(self, plaintext, iv):
        """
        Encrypts `plaintext` using EBC mode and PKCS#7 padding.
        """
    
        plaintext = pad(plaintext)

        blocks = []
        for plaintext_block in split_blocks(plaintext):
            # CBC mode encrypt: encrypt(plaintext_block XOR previous)
            block = self.encrypt_block(plaintext_block)
            blocks.append(block)

        return b''.join(blocks)

    def decrypt_ebc(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using CBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """

        blocks = []
        for ciphertext_block in split_blocks(ciphertext):
            # CBC mode decrypt: previous XOR decrypt(ciphertext)
            blocks.append(self.decrypt_block(ciphertext_block))

        return unpad(b''.join(blocks))

    def encrypt_cbc(self, plaintext, iv):
        """
        Encrypts `plaintext` using CBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 8

        plaintext = pad(plaintext)

        blocks = []
        previous = iv
        for plaintext_block in split_blocks(plaintext):
            # CBC mode encrypt: encrypt(plaintext_block XOR previous)
            block = self.encrypt_block(xor_bytes(plaintext_block, previous))
            blocks.append(block)
            previous = block

        return b''.join(blocks)

    def decrypt_cbc(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using CBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 8

        blocks = []
        previous = iv
        for ciphertext_block in split_blocks(ciphertext):
            # CBC mode decrypt: previous XOR decrypt(ciphertext)
            blocks.append(xor_bytes(previous, self.decrypt_block(ciphertext_block)))
            previous = ciphertext_block

        return unpad(b''.join(blocks))

    def encrypt_pcbc(self, plaintext, iv):
        """
        Encrypts `plaintext` using PCBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 8

        plaintext = pad(plaintext)

        blocks = []
        prev_ciphertext = iv
        prev_plaintext = bytes(16)
        for plaintext_block in split_blocks(plaintext):
            # PCBC mode encrypt: encrypt(plaintext_block XOR (prev_ciphertext XOR prev_plaintext))
            ciphertext_block = self.encrypt_block(xor_bytes(plaintext_block, xor_bytes(prev_ciphertext, prev_plaintext)))
            blocks.append(ciphertext_block)
            prev_ciphertext = ciphertext_block
            prev_plaintext = plaintext_block

        return b''.join(blocks)

    def decrypt_pcbc(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using PCBC mode and PKCS#7 padding, with the given
        initialization vector (iv).
        """
        assert len(iv) == 8

        blocks = []
        prev_ciphertext = iv
        prev_plaintext = bytes(16)
        for ciphertext_block in split_blocks(ciphertext):
            # PCBC mode decrypt: (prev_plaintext XOR prev_ciphertext) XOR decrypt(ciphertext_block)
            plaintext_block = xor_bytes(xor_bytes(prev_ciphertext, prev_plaintext), self.decrypt_block(ciphertext_block))
            blocks.append(plaintext_block)
            prev_ciphertext = ciphertext_block
            prev_plaintext = plaintext_block

        return unpad(b''.join(blocks))

    def encrypt_cfb(self, plaintext, iv):
        """
        Encrypts `plaintext` with the given initialization vector (iv).
        """
        assert len(iv) == 8

        blocks = []
        prev_ciphertext = iv
        for plaintext_block in split_blocks(plaintext, require_padding=False):
            # CFB mode encrypt: plaintext_block XOR encrypt(prev_ciphertext)
            ciphertext_block = xor_bytes(plaintext_block, self.encrypt_block(prev_ciphertext))
            blocks.append(ciphertext_block)
            prev_ciphertext = ciphertext_block

        return b''.join(blocks)

    def decrypt_cfb(self, ciphertext, iv):
        """
        Decrypts `ciphertext` with the given initialization vector (iv).
        """
        assert len(iv) == 8

        blocks = []
        prev_ciphertext = iv
        for ciphertext_block in split_blocks(ciphertext, require_padding=False):
            # CFB mode decrypt: ciphertext XOR decrypt(prev_ciphertext)
            plaintext_block = xor_bytes(ciphertext_block, self.encrypt_block(prev_ciphertext))
            blocks.append(plaintext_block)
            prev_ciphertext = ciphertext_block

        return b''.join(blocks)

    def encrypt_ofb(self, plaintext, iv):
        """
        Encrypts `plaintext` using OFB mode initialization vector (iv).
        """
        assert len(iv) == 8

        blocks = []
        previous = iv
        for plaintext_block in split_blocks(plaintext, require_padding=False):
            # OFB mode encrypt: plaintext_block XOR encrypt(previous)
            block = self.encrypt_block(previous)
            ciphertext_block = xor_bytes(plaintext_block, block)
            blocks.append(ciphertext_block)
            previous = block

        return b''.join(blocks)

    def decrypt_ofb(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using OFB mode initialization vector (iv).
        """
        assert len(iv) == 8

        blocks = []
        previous = iv
        for ciphertext_block in split_blocks(ciphertext, require_padding=False):
            # OFB mode decrypt: ciphertext XOR encrypt(previous)
            block = self.encrypt_block(previous)
            plaintext_block = xor_bytes(ciphertext_block, block)
            blocks.append(plaintext_block)
            previous = block

        return b''.join(blocks)

    def encrypt_ctr(self, plaintext, iv):
        """
        Encrypts `plaintext` using CTR mode with the given nounce/IV.
        """
        assert len(iv) == 8

        blocks = []
        nonce = iv
        for plaintext_block in split_blocks(plaintext, require_padding=False):
            # CTR mode encrypt: plaintext_block XOR encrypt(nonce)
            block = xor_bytes(plaintext_block, self.encrypt_block(nonce))
            blocks.append(block)
            nonce = inc_bytes(nonce)

        return b''.join(blocks)

    def decrypt_ctr(self, ciphertext, iv):
        """
        Decrypts `ciphertext` using CTR mode with the given nounce/IV.
        """
        assert len(iv) == 8

        blocks = []
        nonce = iv
        for ciphertext_block in split_blocks(ciphertext, require_padding=False):
            # CTR mode decrypt: ciphertext XOR encrypt(nonce)
            block = xor_bytes(ciphertext_block, self.encrypt_block(nonce))
            blocks.append(block)
            nonce = inc_bytes(nonce)

        return b''.join(blocks)

def encrypt(key, plaintext, mode = 'cbc', workload=100000, key_size=8):
    """
    Encrypts `plaintext` with `key` using AES-128, an HMAC to verify integrity,
    and PBKDF2 to stretch the given key.

    The exact algorithm is specified in the module docstring.
    """
    if isinstance(key, str):
        key = key.encode('utf-8')
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')

    salt = os.urandom(SALT_SIZE)
    key, hmac_key, iv = get_key_iv(key, salt, key_size, workload)
    ciphertext = LED(key).modes_dict[mode][0](plaintext, iv)
    hmac = new_hmac(hmac_key, salt + ciphertext, 'sha256').digest()
    assert len(hmac) == HMAC_SIZE

    return hmac + salt + ciphertext


def decrypt(key, ciphertext, mode = 'cbc', workload=100000, key_size=8):
    """
    Decrypts `ciphertext` with `key` using AES-128, an HMAC to verify integrity,
    and PBKDF2 to stretch the given key.

    The exact algorithm is specified in the module docstring.
    """

    assert len(ciphertext) % 8 == 0, "Ciphertext must be made of full 16-byte blocks."

    assert len(ciphertext) >= 16, """
    Ciphertext must be at least 32 bytes long (16 byte salt + 16 byte block). To
    encrypt or decrypt single blocks use `AES(key).decrypt_block(ciphertext)`.
    """

    if isinstance(key, str):
        key = key.encode('utf-8')

    hmac, ciphertext = ciphertext[:HMAC_SIZE], ciphertext[HMAC_SIZE:]
    salt, ciphertext = ciphertext[:SALT_SIZE], ciphertext[SALT_SIZE:]
    key, hmac_key, iv = get_key_iv(key, salt, key_size, workload)

    expected_hmac = new_hmac(hmac_key, salt + ciphertext, 'sha256').digest()
    assert compare_digest(hmac, expected_hmac), 'Ciphertext corrupted or tampered.'

    return LED(key).modes_dict[mode][1](ciphertext, iv)

# workload=100000
# salt = os.urandom(SALT_SIZE)
# key, hmac_key, iv = get_key_iv(b'DHRUVDESHMUKH\0\0\0', salt, workload)
# led = LED(key)
print(decrypt(b'DHRUVDES',encrypt(b'DHRUVDES',b'DHRUVDESHMUKH\0\0\0',mode='e',key_size = 16), mode = 'ctr',key_size = 16))
print(encrypt(b'DHRUVDES',b'DHRUVDESHMUKH\0\0\0', mode='ctr',key_size=16))

# print(led.decrypt_block(led.encrypt_block(b'DHRUVDES')))