from database import create_db
from functions import register, login, generate_rsa_keys

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
                if register():
                    print("Já pode fazer login com a sua nova conta.")
            elif option == 2:
                login()
            elif option == 3:
                break
            else:
                print("Opção inválida. Tente novamente.")
        except ValueError:
            print("Opção inválida. Tente novamente.")


if __name__ == "__main__":
    create_db()
    if not os.path.exists("private.pem") or not os.path.exists("public.pem"):
        generate_rsa_keys()
    main_menu()
