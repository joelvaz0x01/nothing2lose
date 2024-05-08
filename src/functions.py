from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256, SHA512
from Crypto.Random import get_random_bytes
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


def encrypt(email, password, aes_mode, hmac_mode, ):
    """
    Encrypts the data and stores it in a file

    Attributes:
    ----------
    data : bytes
        Data to encrypt
    mode_aes : str
        Encryption mode chosen for AES128
    mode_hmac : str
        Encryption mode chosen for HMAC
    email : str
        Email of the user
    """
    key = get_random_bytes(16)  # Chave 128 bits para AES
    iv = get_random_bytes(16)  # IV de 128 bits

    if aes_mode == "AES128-CBC":
        cipher = AES.new(key, AES.MODE_CBC, iv)
    elif aes_mode == "AES128-CTR":
        cipher = AES.new(key, AES.MODE_CTR)
    else:
        raise ValueError("Modo AES não suportado.")

    ciphertext = cipher.encrypt(password)

    if hmac_mode == "HMAC-SHA256":
        hmac_hash = HMAC.new(key, digestmod=SHA256)
    elif hmac_mode == "HMAC-SHA512":
        hmac_hash = HMAC.new(key, digestmod=SHA512)
    else:
        raise ValueError("Modo HMAC não suportado.")

    hmac_hash.update(ciphertext)
    hmac_value = hmac_hash.digest()

    # user key
    with open(f'{email}/key.bin', 'wb') as f:
        f.write(key)

    # encrypted data
    return iv + ciphertext + hmac_value


def decrypt(filename, username, mode_aes, mode_hmac):
    """
    Decrypts and verifies the integrity of the data

    Attributes:
    ----------
    filename : str
        Filename with the encrypted data
    username : str
        Filename with the key
    mode_aes : str
        Encryption mode chosen for AES128
    mode_hmac : str
        Encryption mode chosen for HMAC

    Returns:
    --------
    decrypted_data : bytes
        Decrypted data
    """
    # read the key from the file
    with open(filename, "rb") as f:
        key = f.read()

    # read encrypted data from the database
    with open(f'{username}/key.bin', "rb") as f:
        encrypted_data = f.read()

    iv = encrypted_data[:16]  # the first 16 bytes is IV
    ciphertext = encrypted_data[16:-32]  # exclude the IV and the HMAC
    received_hmac = encrypted_data[-32:]  # the last 32 bytes is HMAC

    if mode_aes == "AES128-CBC":
        cipher = AES.new(key, AES.MODE_CBC, iv)
    elif mode_aes == "AES128-CTR":
        cipher = AES.new(key, AES.MODE_CTR)
    else:
        raise ValueError("Modo AES não suportado.")

    decrypted_data = cipher.decrypt(ciphertext)

    if mode_hmac == "HMAC-SHA256":
        hmac_hash = HMAC.new(key, digestmod=SHA256)
    elif mode_hmac == "HMAC-SHA512":
        hmac_hash = HMAC.new(key, digestmod=SHA512)
    else:
        raise ValueError("Modo HMAC não suportado.")

    hmac_hash.update(ciphertext)
    computed_hmac = hmac_hash.digest()

    if computed_hmac != received_hmac:
        raise ValueError("Verificação do HMAC falhou.")

    return decrypted_data


def register():
    """Function that allows the user to register in the system"""
    while True:
        email = input("Introduza o seu email: ")
        # validate username email regex
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
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
    email = input("Introduza o seu email: ")
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
                prize_s, prize_m, prize_r, prize_l = generate_ticket_prizes()
                # print(f'Prémio Simples: {prize_s}')
                # print(f'Prémio Médio: {prize_m}')
                # print(f'Prémio Raro: {prize_r}')
                # print(f'Prémio Lendário: {prize_l}')

                key_simple = generate_ticket_keys(20)  # Chave para o prémio simples
                key_medium = generate_ticket_keys(21)  # Chave para o prémio médio
                key_rare = generate_ticket_keys(22)  # Chave para o prémio raro
                key_legendary = generate_ticket_keys(23)  # Chave para o prémio lendário
                # print(f'Prémio Simples: {key_simple}')
                # print(f'Prémio Médio: {key_medium}')
                # print(f'Prémio Raro: {key_rare}')
                # print(f'Prémio Lendário: {key_legendary}')
            elif option == 2:
                break
            else:
                print("Opção inválida. Tente novamente.")
        except ValueError:
            print("Opção inválida. Tente novamente.")


def generate_ticket_prizes():
    """
    Generates the prizes for the lottery ticket

    Returns:
    --------
    prize_security : int
        Security level of the prize
    """
    key = []
    prize_security = secrets.randbelow(10)
    for i in range(4):
        key.append(2 ** (prize_security + i))
    return key


def generate_ticket_keys(random_bits):
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
    key = rand_key_bin + '0' * (128 - random_bits)
    return key


"""
def encrypt(filename, key):
    f = Fernet(key)
    with open(filename, "rb") as file:
        file_data = file.read()
    encrypted_data = f.encrypt(file_data)
    with open(filename, "wb") as file:
        file.write(encrypted_data)


def decrypt(filename, key):
    f = Fernet(key)
    try:
        with open(filename, "rb") as file:
            encrypted_data = file.read()
        decrypted_data = f.decrypt(encrypted_data)
        with open(filename, "wb") as file:
            file.write(decrypted_data)
        return True
    except (crypto.fernet.InvalidToken, TypeError):
        return False
"""
