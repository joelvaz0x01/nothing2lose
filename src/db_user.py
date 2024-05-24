import base64
import hashlib
import os
import sqlite3


def create_db():
    """Function to create the database and tables"""
    global sql_connection
    try:
        sql_connection = sqlite3.connect("users.db")
        cursor = sql_connection.cursor()

        # create table users if it doesn't exist
        cursor.execute("CREATE TABLE IF NOT EXISTS users (username text, password text, ticket_s text, ticket_m text, "
                       "ticket_r text, ticket_l text)")

        sql_connection.commit()
        cursor.close()

    except sqlite3.Error as error:
        print("Erro ao criar a base de dados: ", error)


def add_user(user, password):
    """
    Function to add new users to the database

    Attributes:
    ----------
    user : str
        Email of the user
    hash_pass : str
        Password of the user (in plaintext)
    """
    hash_pass = hash_password(password)
    cursor = sql_connection.cursor()
    user_values = [(user, hash_pass)]
    cursor.executemany("INSERT INTO users (username, password) VALUES (?,?)", user_values)
    sql_connection.commit()
    cursor.close()
    return


def add_ticket(user, tickets):
    """
    Function to add a ticket to a user

    Attributes:
    ----------
    user : str
        Email of the user
    tickets : list
        List of tickets to be added to the user
    """
    cursor = sql_connection.cursor()
    cursor.execute("UPDATE users SET ticket_s = ?, ticket_m = ?, ticket_r = ?, ticket_l = ? WHERE username = ?",
                   (tickets[0], tickets[1], tickets[2], tickets[3], user))
    sql_connection.commit()
    cursor.close()
    return


def get_tickets(user, ticket_type):
    """
    Function to get the tickets of a user

    Attributes:
    ----------
    user : str
        Email of the user

    Returns:
    --------
    list
        List of tickets of the user
    """
    cursor = sql_connection.cursor()
    for row in cursor.execute("SELECT * from users WHERE username = ?", (user,)):
        cursor.close()
        return row[2 + ticket_type]
    cursor.close()
    return None


def email_exists(user):
    """
    Function to check if a user already exists in the database

    Attributes:
    ----------
    user : str
        Email of the user

    Returns:
    --------
    bool
        True if the user already exists, False otherwise
    """
    cursor = sql_connection.cursor()
    for row in cursor.execute("SELECT * from users"):
        if user == row[0]:
            cursor.close()
            return True
    cursor.close()
    return False


def hash_password(password):
    """
    Function to hash and salt a password

    Attributes:
    ----------
    password : str
        Password of the user (in plaintext)

    Returns:
    --------
    str
        Encrypted password of the user (salted + hashed)
    """
    salt = os.urandom(32)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return base64.b64encode(salt).decode() + base64.b64encode(key).decode()


def verify_password(stored_password, provided_password):
    """
    Function to confirm if the encrypted password is equal to the encrypted password stored in the database

    Attributes:
    ----------
    stored_password : str
        Encrypted password of the user on the database (salted + hashed)
    provided_password : str
        Password provided by the user (in plaintext)

    Returns:
    --------
    bool
        True if the passwords match, False otherwise
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

    salt = base64.b64decode(stored_password[:44])  # first 44 characters is salt
    stored_key = base64.b64decode(stored_password[44:])  # rest is the hashed password
    new_key = hashlib.pbkdf2_hmac('sha256', provided_password.encode('utf-8'), salt, 100000)
    return stored_key == new_key


def verify_email_password(email, password):
    """
    Function to check if a user exists in the database and if the password is correct

    Attributes:
    ----------
    email : str
        Email provided by the user
    password : str
        Password provided by the user (in plaintext)

    Returns:
    --------
    bool
        True if the user exists and the password is correct, False otherwise
    """
    cursor = sql_connection.cursor()
    for row in cursor.execute('SELECT * from users WHERE username = ?', (email,)):
        if email == row[0] and verify_password(row[1], password):
            cursor.close()
            return True
    cursor.close()
    return False


def get_half_ticket(ticket_type):
    """
    Function to get half tickets for a specific type

    Attributes:
    ----------
    ticket_type : int
        Type of ticket to be returned

    Returns:
    --------
    str
        Half ticket for the specified type
    """
    cursor = sql_connection.cursor()
    for row in cursor.execute("SELECT * from users"):
        cursor.close()
        return row[2 + ticket_type][:44]
    cursor.close()
    return None