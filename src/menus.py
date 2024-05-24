from base64 import b64encode

from brute_force import start_brute_force
from crypto import generate_prizes, generate_prize_keys, encrypt
from db_user import add_ticket
from rsa import sign_rsa, load_rsa_private_key


def dashboard_menu(email):
    """
    Dashboard menu for the user

    Attributes:
    ----------
    email : str
        Email of the user
    """
    encrypted_prizes = []
    half_keys = []
    aes_mode = None
    hmac_mode = None

    while True:
        try:
            print(f'\nDashboad de {email}')
            print("1 - Gerar bilhetes de lotaria")
            if encrypted_prizes:
                print("2 - Realizar brute force")
            print("3 - Fazer logout")
            option = int(input("Selecione a opção desejada: "))
            if option == 1:
                aes_mode = aes_menu()
                hmac_mode = hmac_menu()
                prize_s, prize_m, prize_r, prize_l = generate_prizes()

                # generate the keys for the prizes
                keys = [
                    generate_prize_keys(22),  # simple
                    generate_prize_keys(24),  # medium
                    generate_prize_keys(26),  # rare
                    generate_prize_keys(28)  # legendary
                ]

                half_keys = [key[:len(key) // 2] for key in keys]

                # encrypt the prizes with the respective keys
                encrypted_prizes = [
                    encrypt(prize_s, keys[0], aes_mode, hmac_mode),
                    encrypt(prize_m, keys[1], aes_mode, hmac_mode),
                    encrypt(prize_r, keys[2], aes_mode, hmac_mode),
                    encrypt(prize_l, keys[3], aes_mode, hmac_mode)
                ]

                # digest and sign the keys
                sign_keys = [
                    sign_rsa(load_rsa_private_key(), keys[0]),
                    sign_rsa(load_rsa_private_key(), keys[1]),
                    sign_rsa(load_rsa_private_key(), keys[2]),
                    sign_rsa(load_rsa_private_key(), keys[3])
                ]

                # encode the keys to base64
                sign_keys_base64 = [
                    b64encode(sign_keys[0]).decode('utf-8'),
                    b64encode(sign_keys[1]).decode('utf-8'),
                    b64encode(sign_keys[2]).decode('utf-8'),
                    b64encode(sign_keys[3]).decode('utf-8')
                ]

                add_ticket(email, sign_keys_base64)  # add the tickets to the database

                print("\nPrémios gerados com sucesso!\n")
            elif encrypted_prizes and half_keys and aes_mode is not None and hmac_mode is not None and option == 2:
                brute_force_menu(email, encrypted_prizes, half_keys, aes_mode, hmac_mode)
            elif option == 3:
                break
            else:
                print("Opção inválida. Tente novamente.")
        except ValueError:
            print("Opção inválida. Tente novamente.")


def aes_menu():
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


def hmac_menu():
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


def brute_force_menu(email, encrypted_prizes, half_keys, aes_mode, hmac_mode):
    """Menu for the brute force mode"""
    s_is_decrypted = False
    m_is_decrypted = False
    r_is_decrypted = False
    l_is_decrypted = False

    while True:
        try:
            print("\nEscolha o prémio que deseja fazer brute force:")
            if not s_is_decrypted:
                print("1 - Prémio simples")
            if not m_is_decrypted:
                print("2 - Prémio médio")
            if not r_is_decrypted:
                print("3 - Prémio raro")
            if not l_is_decrypted:
                print("4 - Prémio lendário")
            if s_is_decrypted and m_is_decrypted and r_is_decrypted and l_is_decrypted:
                print("Todos os prémios foram decifrados!")
                break
            print("5 - Sair do modo de brute-force")
            option = int(input("Selecione a opção desejada: "))
            if not s_is_decrypted and option == 1:
                s_is_decrypted = start_brute_force(
                    encrypted_prizes[0],
                    "simple",
                    half_keys[0],
                    email,
                    aes_mode,
                    hmac_mode
                )
            elif not m_is_decrypted and option == 2:
                m_is_decrypted = start_brute_force(
                    encrypted_prizes[1],
                    "medium",
                    half_keys[1],
                    email,
                    aes_mode,
                    hmac_mode
                )
            elif not r_is_decrypted and option == 3:
                r_is_decrypted = start_brute_force(
                    encrypted_prizes[2],
                    "rare",
                    half_keys[2],
                    email,
                    aes_mode,
                    hmac_mode
                )
            elif not l_is_decrypted and option == 4:
                l_is_decrypted = start_brute_force(
                    encrypted_prizes[3],
                    "legendary",
                    half_keys[3],
                    email,
                    aes_mode,
                    hmac_mode
                )
            elif option == 5:
                break
        except ValueError:
            print("Opção inválida. Tente novamente.")
