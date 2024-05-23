import json
from base64 import b64encode, b64decode

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256, SHA512
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from database import add_user, email_exists, verify_email_password
from getpass import getpass
from pwinput import pwinput
import re
import secrets


def select_aes():
    """
    Function that allows the user to choose the encryption mode of AES128

    Returns:
    --------
    mode : str
        Encryption mode chosen for AES128
    """

    while True:
        try:
            print("\nEscolha a cifra a utilizar:")
            print("1 - AES128-CBC")
            print("2 - AES128-CTR")
            opt = int(input("Escolha entre as opções: "))
            if opt == 1:
                return "AES128-CBC"
            elif opt == 2:
                return "AES128-CTR"
            else:
                print("Opção inválida. Tente novamente.")
        except ValueError:
            print("Opção inválida. Tente novamente.")


def select_hmac():
    """
    Function that allows the user to choose the encryption mode for HMAC

    Returns:
    --------
    mode : str
        Encryption mode chosen for HMAC
    """
    while True:
        try:
            print("\nEscolha a função HMAC a utilizar:")
            print("1 - HMAC-SHA256")
            print("2 - HMAC-SHA512")
            opt = int(input("Escolha entre as opções: "))
            if opt == 1:
                return "HMAC-SHA256"
            elif opt == 2:
                return "HMAC-SHA512"
            else:
                print("Opção inválida. Tente novamente.")
        except ValueError:
            print("Opção inválida. Tente novamente.")


def encrypt(prize, key, aes_mode, hmac_mode):
    """
    Encrypts the data and stores it in a file

    Attributes:
    ----------
    prize : bytes
        Data to be encrypted
    key : bytes
        Key used for encryption
    mode_aes : str
        Encryption mode chosen for AES128
    mode_hmac : str
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
        pt_bytes = unpad(cipher.decrypt(ct), AES.block_size)
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
        raise ValueError("HMAC verification failed.")

    # convert the plaintext bytes to a big integer
    pt = int.from_bytes(pt_bytes, 'big')

    return pt


def check_email(email):
    return re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email)


def register():
    """Function that allows the user to register in the system"""
    while True:
        email = input("Introduza o seu email [prima ENTER para sair]: ")
        # validate username email regex
        if not email:
            return
        elif not check_email(email):
            print("O email introduzido não é válido.\n")
        elif email_exists(email):
            print("O email introduzido já existe.\n")
        else:
            break

    while True:
        password = getpass("Introduza a sua password: ")
        password_confirmation = getpass("Confirme a sua password: ")
        if len(password) < 8:
            print("A password deve ter pelo menos 8 caracteres.\n")
        elif password != password_confirmation:
            print("As passwords não coincidem.\n")
        else:
            break

    add_user(email, password)
    print("Registado com sucesso!")
    return


def login():
    """Function that allows the user to login in the system"""
    while True:
        email = input("Introduza o seu email [prima ENTER para sair]: ")
        if not email:
            return
        if not check_email(email):
            break

    password = getpass("Introduza a sua password: ")
    if email_exists(email):
        if verify_email_password(email, password):
            print("Login efetuado com sucesso!\n")
            dashboard_menu(email)
        else:
            print("Password incorreta. Tente novamente.\n")
    else:
        print("O email introduzido não existe.\n")


def dashboard_menu(email):
    """
    Dashboard menu for the user

    Attributes:
    ----------
    email : str
        Email of the user
    """
    while True:
        try:
            print(f'\nDashboad de {email}')
            print("1 - Gerar bilhetes de lotaria")
            print("2 - Fazer logout")
            option = int(input("Selecione a opção desejada: "))
            if option == 1:
                aes_mode = select_aes()
                hmac_mode = select_hmac()
                prize_s, prize_m, prize_r, prize_l = generate_prizes()

                # generate the keys for the prizes
                key_simple = generate_prize_keys(20)
                key_medium = generate_prize_keys(21)
                key_rare = generate_prize_keys(22)
                key_legendary = generate_prize_keys(23)

                # encrypt the prizes with the respective keys
                encrypted_prize_s = encrypt(prize_s, key_simple, aes_mode, hmac_mode)
                encrypted_prize_m = encrypt(prize_m, key_medium, aes_mode, hmac_mode)
                encrypted_prize_r = encrypt(prize_r, key_rare, aes_mode, hmac_mode)
                encrypted_prize_l = encrypt(prize_l, key_legendary, aes_mode, hmac_mode)

                print("\nPrémios gerados com sucesso!")
            elif option == 2:
                break
            else:
                print("Opção inválida. Tente novamente.")
        except ValueError:
            print("Opção inválida. Tente novamente.")


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
    # generate a random key
    rand_key = secrets.randbits(random_bits)

    # convert to binary
    rand_key_bin = f'{rand_key:b}'

    # fill the rest of the key with zeros up to 128 bits
    key_binary = rand_key_bin + '0' * (128 - random_bits)

    # convert the key to bytes
    key = int(key_binary, 2).to_bytes(16, 'big')

    return key
