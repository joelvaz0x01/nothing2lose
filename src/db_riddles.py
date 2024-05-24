import base64
import hashlib
import os
import sqlite3


def create_riddle_db():
    """Function to create the riddles database"""
    global sql_connection_riddles
    try:
        sql_connection_riddles = sqlite3.connect('riddles.db')
        cursor = sql_connection_riddles.cursor()

        # Create the table riddles if it doesn't exist
        cursor.execute("CREATE TABLE riddles (riddle text, answer text)")
        sql_connection_riddles.commit()
        cursor.close()
        return True

    except sqlite3.Error as error:
        print("Erro ao criar a base de dados: ", error)
        return False


def add_riddle(riddle_to_add, answer_to_add):
    """
    Function to add a riddle to the database

    Attributes:
    ----------
    riddle : str
        Riddle to be added
    answer : str
        Answer to the riddle
    """
    hash_answer = hash_riddle_answer(answer_to_add)
    cursor = sql_connection_riddles.cursor()
    riddle_values = [(riddle_to_add, hash_answer)]
    cursor.executemany("INSERT INTO riddles (riddle, answer) VALUES (?,?)", riddle_values)
    sql_connection_riddles.commit()
    cursor.close()
    return


def hash_riddle_answer(answer):
    """
    Function to hash and salt a password

    Attributes:
    ----------
    answer : str
        Answer to be hashed

    Returns:
    --------
    str
        Encrypted answer of the riddle (salted + hashed)
    """
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', answer.encode('utf-8'), salt, 100000)
    return base64.b64encode(salt).decode() + base64.b64encode(key).decode()


def get_random_riddle():
    """
    Function to get a random riddle from the database

    Returns:
    --------
    str
        Random riddle from the database
    """
    cursor = sql_connection_riddles.cursor()
    cursor.execute("SELECT * FROM riddles ORDER BY RANDOM() LIMIT 1")
    riddle, _ = cursor.fetchone()
    cursor.close()
    return riddle


def check_riddle_answer(answer, hashed_answer):
    """
    Function to check if the answer is correct

    Attributes:
    ----------
    answer : str
        Answer to be checked
    hashed_answer : str
        Hashed answer to be compared

    Returns:
    --------
    bool
        True if the answer is correct, False otherwise
    """

    # Brief explanation of why 44 characters are used on salt:
    # ---------------------------------------------------------
    # base64 encoding uses 4 characters to represent 3 bytes
    # and uses 64 different characters (26 lowercase, 26 uppercase, 10 digits, + and /)
    # 6 bits is enough to represent 64 different characters because 2^6 = 64
    # 1 byte = 8 bits, so 8/6 = 1.3333 characters per byte on base64
    # salt is 32 bytes long, so 32 * 1.3333 = 42.664 characters
    # but base64 encoding always rounds up to the nearest multiple of 4 (padding)
    # so 44 characters are used to represent 32 bytes of data (salt is 44 characters long)

    salt = base64.b64decode(hashed_answer[:44])
    stored_answer = base64.b64decode(hashed_answer[44:])
    new_answer = hashlib.pbkdf2_hmac('sha256', answer.encode('utf-8'), salt, 100000)
    return stored_answer == new_answer


def verify_riddle_answer(riddle, answer):
    """
    Function to verify if the answer is correct

    Attributes:
    ----------
    riddle : str
        Riddle to be checked
    answer : str
        Answer to be checked

    Returns:
    --------
    bool
        True if the answer is correct, False otherwise
    """
    cursor = sql_connection_riddles.cursor()
    cursor.execute("SELECT answer FROM riddles WHERE riddle = ?", (riddle,))
    hashed_answer = cursor.fetchone()
    cursor.close()
    if hashed_answer is None:
        return False
    return check_riddle_answer(answer, hashed_answer[0])
