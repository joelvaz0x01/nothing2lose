import hashlib
import sqlite3


def create_db():
    """
    Função para criar a base de dados
    """
    global sql_connection
    try:
        sql_connection = sqlite3.connect("users.db")
        cursor = sql_connection.cursor()

        # cria tabela de utilizadores se ainda nao foi criada
        cursor.execute("CREATE TABLE IF NOT EXISTS users (username text, password text, user_key text)")

        # cria tabela de utilizadores se ainda nao foi criada
        cursor.execute("CREATE TABLE IF NOT EXISTS salt (salt_val BLOB)")

        sql_connection.commit()
        cursor.close()

    except sqlite3.Error as error:
        print("Erro ao criar a base de dados: ", error)


def add_user(user, password, key):
    """
    Função para guardar novos utilizadores na base de dados

    Atributes:
    ----------
    user : str
        Nome do utilizador
    password : str
        Password do utilizador
    key : str
        Chave de encriptação do utilizador
    """
    cursor = sql_connection.cursor()
    user_values = [(user, password, key)]
    cursor.executemany("INSERT INTO users (username, password, user_key) VALUES (?,?,?)", user_values)
    sql_connection.commit()
    cursor.close()
    return


# for row in cursor.execute("select * from users"):  # mostra tabela(pode ser eliminada no último commit)
#     print(row)


def email_exists(user):
    """
    Função para verificar se um utilizador já existe na base de dados

    Atributes:
    ----------
    user : str
        Nome do utilizador

    Returns:
    --------
    bool
        True se o utilizador já existe, False caso contrário
    """
    cursor = sql_connection.cursor()
    for row in cursor.execute("SELECT * from users"):
        if user == row[0]:
            cursor.close()
            return True
    cursor.close()
    return False


def add_salt(salt):
    lista = bytearray(salt)
    cursor = sql_connection.cursor()
    cursor.execute("INSERT INTO salt (salt_val) VALUES (?)", (lista,))
    sql_connection.commit()
    cursor.close()
    return


def get_user_key(usr):
    cursor = sql_connection.cursor()
    for k in cursor.execute(f'SELECT user_key FROM users WHERE username = {usr}'):
        cursor.close()
        return k[0]
    sql_connection.commit()
    cursor.close()
    return


def confirm_pass(p, p2):
    """
    Função que confirma se a palavra-chave encriptada é igual à palavra-chave encriptada guardada na base de dados

    Atributes:
    ----------
    p : str
        Palavra-chave encriptada
    p2 : str
        Palavra-chave encriptada guardada na base de dados

    Returns:
    --------
    bool
        True se as palavras-chave forem iguais, False caso contrário
    """
    cursor = sql_connection.cursor()
    for r in cursor.execute("SELECT * FROM salt"):
        salt = r[0]
        salt2 = bytes(salt)
        hp = hashlib.pbkdf2_hmac('sha256', p.encode(), salt2, 10000)
        print("Passe encriptada\n")
        print(hp)
        if hp == p2:
            return True
    return False


def verify_email_password(email, password):
    """
    Função para verificar se um utilizador existe na base de dados e se a palavra-chave está correta

    Atributes:
    ----------
    email : str
        Nome do utilizador
    password : str
        Palavra-chave do utilizador

    Returns:
    --------
    bool
        True se o utilizador existe e a palavra-chave está correta, False caso contrário
    """
    cursor = sql_connection.cursor()
    for row in cursor.execute(f'SELECT * from users WHERE username = {email}'):
        if email == row[0] and confirm_pass(password, row[1]):
            cursor.close()
            return True
    cursor.close()
    return False
