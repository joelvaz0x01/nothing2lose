import sqlite3

from database import add_user, email_exists, verify_email_password
import pwinput
import hashlib
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256, SHA512
from Crypto.Random import get_random_bytes
import os
import re
import secrets


def select_aes():
    """
    Função que permite ao utilizador escolher o modo de encriptação

    Returns:
    --------
    mode : str
        Modo de encriptação escolhido para AES128
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
    Função que permite ao utilizador escolher o modo de encriptação

    Returns:
    --------
    mode : str
        Modo de encriptação escolhido para HMAC
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
    Gera uma chave e guarda-a num ficheiro

    Atributes:
    ----------
    data : bytes
        Dados a encriptar
    mode_aes : str
        Modo de encriptação para AES128
    mode_hmac : str
        Modo de encriptação para HMAC
    username : str
        Nome do utilizador
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

    # Chave do utilizador
    with open(f'{email}/key.bin', 'wb') as f:
        f.write(key)

    # Dados encriptados
    # TODO: Guardar os dados encriptados na base de dados
    return iv + ciphertext + hmac_value


"""
with open("encrypted_data.bin", "wb") as f:
    f.write(iv + ciphertext + hmac_value)
"""


def decrypt(file_name, username, mode_aes, mode_hmac):
    """
    Desencripta e verifica a integridade dos dados

    Atributes:
    ----------
    file_name : str
        Nome do ficheiro com os dados encriptados
    username : str
        Nome do ficheiro com a chave
    mode_aes : str
        Modo de encriptação para AES128
    mode_hmac : str
        Modo de encriptação para HMAC

    Returns:
    --------
    decrypted_data : bytes
        Dados desencriptados
    """
    # Ler chave do utilizador
    with open(file_name, "rb") as f:
        key = f.read()

    # Ler dados encriptados da base de dados
    # TODO: Ler a chave da base de dados
    with open(f'{username}/key.bin', "rb") as f:
        encrypted_data = f.read()

    iv = encrypted_data[:16]  # Os primeiros 16 bytes são o IV
    ciphertext = encrypted_data[16:-32]  # Excluir IV e HMAC
    received_hmac = encrypted_data[-32:]  # Os últimos 32 bytes são o HMAC

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


"""
def cipher(p):
    salt = os.urandom(32)
    add_salt(salt)
    p = p.encode()
    hp = hashlib.pbkdf2_hmac('sha256', p, salt, 10000)
    return hp

"""


def register():
    """Função que permite ao utilizador registar-se no sistema"""
    aes_mode = select_aes()
    hmac_mode = select_hmac()

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
        password = pwinput.pwinput("Introduza a sua password: ", mask='')
        password_confirmation = pwinput.pwinput("Confirme a sua password:")
        if len(password) < 8:
            print("A password deve ter pelo menos 8 caracteres.\n")
        elif password != password_confirmation:
            print("As passwords não coincidem.\n")
        else:
            break

    print("Registado com sucesso!")
    hp = cipher(password)
    # key = Fernet.generate_key()
    add_user(email, hp, key)
    currentDir = os.getcwd()  # Indica a diretoria actual
    newDir = email  # Iguala o nome da nova diretoria ao nome do utilizador
    pth = os.path.join(currentDir, newDir)  # Junta o nome da nova diretoria à diretoria actual
    os.mkdir(pth)  # Cria a diretoria
    # os.chdir(currentDir + "/" + u) #muda para a diretoria do novo user
    print(os.getcwd())
    return


def login(aes_mode, hmac_mode):
    """
    Função que permite ao utilizador fazer login no sistema

    Atributes:
    ----------
    mode_aes : str
        Modo de encriptação para AES128
    mode_hmac : str
        Modo de encriptação para HMAC
    """
    email = input("Introduza o seu username: ")
    password = pwinput.pwinput("Introduza a sua password: ")
    ciphertext = encrypt(email, password, aes_mode, hmac_mode)
    if email_exists(email):
        if verify_email_password(email, ciphertext):
            print("Login efetuado com sucesso!\n")
            current_dir = os.getcwd()  # Indica a diretoria actual
            print(current_dir)
            usr_dir = current_dir + "/" + email
            os.chdir(usr_dir)  # muda para a diretoria do novo user
            print(os.getcwd())
            dashboard_menu(email)
        else:
            print("Password incorreta. Tente novamente.\n")
    else:
        print("O email introduzido não existe.\n")


def dashboard_menu(email):
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
    Gera os prémios para o bilhete de lotaria

    Returns:
    --------
    prize_security : int
        Nível de segurança do prémio
    """
    key = []
    prize_security = secrets.randbelow(10)
    for i in range(4):
        key.append(2 ** (prize_security + i))
    return key


def generate_ticket_keys(random_bits):
    """
    Gera uma chave de 128 bits com uma parte aleatória de tamanho random_bits

    Atributes:
    ----------
    random_bits : int
        Tamanho da parte aleatória da chave

    Returns:
    --------
    key : str
        Chave gerada
    """
    # Gerar bits aleatórios
    rand_key = secrets.randbits(random_bits)

    # Converter para binário
    rand_key_bin = f'{rand_key:b}'

    # Preencher o resto da chave com zeros até 128 bits
    key = rand_key_bin + '0' * (128 - random_bits)
    return key


"""
def load_key_for_encryption():
   lines = open("key.key", "rb").readlines()
   return lines[len(lines)-1]
"""

"""
def load_key_for_decryption(f):
    lines = open("key.key", "r").readlines()
    waitingFiles = os.getcwd() + "\waitingFiles"   
    os.chdir(waitingFiles)
    keyFound = False
    while not keyFound:
        for key in lines:
            print(key)
            if decrypt(f, key):
                remove_key_from_file(key)
                return True
            else:
                continue
        break
    return False
"""

"""
def remove_key_from_file(key):
    lines = open("key.key", "r").readlines()
    with open("key.key", "w") as f:
        for k in lines:
            if k != key:
                f.write(k)
"""

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
