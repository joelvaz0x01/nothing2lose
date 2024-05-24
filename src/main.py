from db_riddles import create_riddle_db, add_riddle
from db_user import create_db
from rsa import generate_rsa_keys
from user_management import register, login

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
    # Check if the database files exist, if not create them
    if not os.path.exists("users.db"):
        create_db()

    # Check if the riddles database file exists, if not create it and add the riddles from the riddles.txt file
    if not os.path.exists("riddles.db"):
        create_riddle_db()
        with open("riddles.txt", "r") as file:
            for line in file:
                riddle_file, answer_file = line.split(";")
                answer_file = answer_file[:-1].lower()  # ignore new line character at lower case the riddle
                add_riddle(riddle_file, answer_file)

    # Check if the RSA keys exist, if not generate them
    if not os.path.exists("private_key.pem") or not os.path.exists("public_key.pem"):
        generate_rsa_keys()

    # Start the main menu
    main_menu()
