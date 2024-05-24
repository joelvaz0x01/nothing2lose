from db_riddles import create_riddle_db, add_riddle
from db_user import create_db
from menus import main_menu
from rsa import generate_rsa_keys

import os

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
