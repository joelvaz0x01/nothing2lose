import json
import secrets

from base64 import b64encode, b64decode

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256, SHA512
from Crypto.Util.Padding import pad


def encrypt(prize, key, aes_mode, hmac_mode):
    """
    Encrypts the data and stores it in a file

    Attributes:
    ----------
    prize : bytes
        Data to be encrypted
    key : bytes
        Key used for encryption
    aes_mode : str
        Encryption mode chosen for AES128
    hmac_mode : str
        Encryption mode chosen for HMAC
    """
    # calculate the number of bytes needed to represent the prize
    # _ // 8 to convert bits to bytes
    # _ + 1 because // operator rounds down
    num_bytes = (prize.bit_length() // 8) + 1

    if aes_mode == "AES128-CBC":
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(prize.to_bytes(num_bytes, 'big'), AES.block_size))
    elif aes_mode == "AES128-CTR":
        cipher = AES.new(key, AES.MODE_CTR)
        ct_bytes = cipher.encrypt(prize.to_bytes(num_bytes, 'big'))
    else:
        raise ValueError("Unsupported AES mode.")

    if hmac_mode == "HMAC-SHA256":
        hmac_hash = HMAC.new(key, digestmod=SHA256)
    elif hmac_mode == "HMAC-SHA512":
        hmac_hash = HMAC.new(key, digestmod=SHA512)
    else:
        raise ValueError("Unsupported HMAC mode.")

    hmac_hash.update(ct_bytes)  # update the HMAC with the ciphertext
    hmac_value = hmac_hash.digest()  # get the HMAC value

    if aes_mode == "AES128-CBC":
        iv = b64encode(cipher.iv).decode('utf-8')  # encode the IV to base64
        ct = b64encode(ct_bytes).decode('utf-8')  # encode the ciphertext to base64
        hmac = b64encode(hmac_value).decode('utf-8')  # encode the HMAC to base64
        result = json.dumps({'iv': iv, 'ciphertext': ct, 'hmac': hmac})
    else:
        nonce = b64encode(cipher.nonce).decode('utf-8')  # encode the nonce to base64
        ct = b64encode(ct_bytes).decode('utf-8')  # encode the ciphertext to base64
        hmac = b64encode(hmac_value).decode('utf-8')  # encode the HMAC to base64
        result = json.dumps({'nonce': nonce, 'ciphertext': ct, 'hmac': hmac})

    return result


def decrypt(encrypted_prize, key, mode_aes, mode_hmac):
    """
    Decrypts and verifies the integrity of the data

    Attributes:
    ----------
    encrypted_prize : bytes
        Encrypted data
    key : bytes
        Key used for decryption
    mode_aes : str
        Encryption mode chosen for AES128
    mode_hmac : str
        Encryption mode chosen for HMAC

    Returns:
    --------
    decrypted_data : bytes
        Decrypted data
    """
    data = json.loads(encrypted_prize)

    ct = b64decode(data['ciphertext'])  # decode the ciphertext from base64
    hmac = b64decode(data['hmac'])  # decode the HMAC from base64

    if mode_aes == "AES128-CBC":
        iv = b64decode(data['iv'])  # decode the IV from base64
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        pt_bytes = cipher.decrypt(ct)
    elif mode_aes == "AES128-CTR":
        nonce = b64decode(data['nonce'])  # decode the nonce from base64
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        pt_bytes = cipher.decrypt(ct)
    else:
        raise ValueError("Unsupported AES mode.")

    if mode_hmac == "HMAC-SHA256":
        hmac_hash = HMAC.new(key, digestmod=SHA256)
    elif mode_hmac == "HMAC-SHA512":
        hmac_hash = HMAC.new(key, digestmod=SHA512)
    else:
        raise ValueError("Unsupported HMAC mode.")

    hmac_hash.update(ct)  # update the HMAC instance with the ciphertext

    # verify if the HMAC value is correct
    if hmac_hash.digest() != hmac:
        return [-1, -1, False]  # [decrypted_data, key, is_decrypted]

    # convert the plaintext bytes to a big integer
    pt = int.from_bytes(pt_bytes, 'big')
    return [pt, key, True]  # [decrypted_data, key, is_decrypted]


def convert_key_to_hex(key):
    """
    Converts the key to bytes

    Attributes:
    ----------
    prize : int
        Prize to be converted to bytes

    Returns:
    --------
    prize_bytes : bytes
        Prize converted to bytes
    """
    key_in_binary = f'{key:b}'
    bit_length = len(key_in_binary)
    final_key_binary = key_in_binary + '0' * (128 - bit_length)  # fill the rest of the key with zeros
    final_key_hex = int(final_key_binary, 2).to_bytes(16, 'big')
    return final_key_hex


def generate_prize_keys(random_bits):
    """
    Generates a 128-bit key with a random part of size random_bits

    Attributes:
    ----------
    random_bits : int
        Size of the random part of the key

    Returns:
    --------
    key : str
        Generated key
    """
    rand_key = secrets.randbits(random_bits)  # generate a random key
    return convert_key_to_hex(rand_key)


def generate_prizes():
    """
    Generates the prizes for the lottery ticket

    Returns:
    --------
    prize_security : int[]
        Prizes for the lottery ticket
    """
    key = []
    prize_security = secrets.randbelow(10)
    for i in range(4):
        key.append(2 ** (prize_security + i))
    return key
