from getpass import getpass

from db_user import add_user, email_exists, verify_email_password
from menus import dashboard_menu

import re


def check_email_format(email):
    """
    Function that checks if the email is valid

    Attributes:
    ----------
    email : str
        Email to be validated
    """
    return re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email)


def register():
    """Function that allows the user to register in the system"""
    while True:
        email = input("Introduza o seu email [prima ENTER para sair]: ")
        if not email:
            return
        elif not check_email_format(email):
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
    print("Utilizador registado com sucesso!")
    print("Já pode fazer login com a sua nova conta.\n")
    return


def login():
    """Function that allows the user to login in the system"""
    while True:
        email = input("Introduza o seu email [prima ENTER para sair]: ")
        if not email:
            return
        if check_email_format(email):
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
