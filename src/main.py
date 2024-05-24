from src.db_user import create_db
from src.user_management import register, login
from src.rsa import generate_rsa_keys

import os


def main_menu():
    """Main menu of the program"""
    while True:
        try:
            print("\nNOTHING2LOSE")
            print("1 - Registar novo utilizador")
            print("2 - Login com utilizador existente")
            print("3 - Sair de NOTHING2LOSE\n")
            option = int(input("Selecione a opção desejada: "))
            if option == 1:
                register()
            elif option == 2:
                login()
            elif option == 3:
                exit(0)
            else:
                print("Opção inválida. Tente novamente.")
        except ValueError:
            print("Opção inválida. Tente novamente.")


if __name__ == "__main__":
    create_db()
    if not os.path.exists("private_key.pem") or not os.path.exists("public_key.pem"):
        generate_rsa_keys()
    main_menu()
