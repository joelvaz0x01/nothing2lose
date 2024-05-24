from base64 import b64decode

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

from src.db_user import get_tickets


def generate_rsa_keys():
    """
    Function that generates RSA keys (2048 bits)

    Returns:
    --------
    private_key : bytes
        Private key generated
    public_key : bytes
        Public key generated
    """
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open("private_key.pem", "wb") as f:
        f.write(private_key)

    with open("public_key.pem", "wb") as f:
        f.write(public_key)

    return private_key, public_key


def load_rsa_public_key():
    """
    Function that loads the RSA public key

    Returns:
    --------
    private_key : bytes
        Private key loaded
    public_key : bytes
        Public key loaded
    """
    with open("public_key.pem", "rb") as f:
        public_key = f.read()
    return public_key


def load_rsa_private_key():
    """
    Function that loads the RSA private key

    Returns:
    --------
    private_key : bytes
        Private key loaded
    public_key : bytes
        Public key loaded
    """
    with open("private_key.pem", "rb") as f:
        private_key = f.read()
    return private_key


def sign_rsa(private_key, message):
    """
    Function that signs a message with a private key

    Attributes:
    ----------
    private_key : bytes
        Private key used to sign the message
    message : bytes
        Message to be signed

    Returns:
    --------
    signature : bytes
        Signature of the message
    """
    key = RSA.import_key(private_key)
    h = SHA256.new(message)
    signature = pkcs1_15.new(key).sign(h)
    return signature


def verify_rsa(public_key, message, signature):
    """
    Function that verifies a message with a public key

    Attributes:
    ----------
    public_key : bytes
        Public key used to verify the message
    message : bytes
        Message to be verified
    signature : bytes
        Signature of the message

    Returns:
    --------
    bool
        True if the message is verified, False otherwise
    """
    key = RSA.import_key(public_key)
    h = SHA256.new(message)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False


def verify_ticket_key(key, ticket_type, user):
    """
    Verifies the key of the ticket

    Attributes:
    ----------
    key : bytes
        Key to be verified
    ticket_type : str
        Type of the ticket

    Returns:
    bool
        True if the key is verified, False otherwise
    """
    id_ticket = -1

    if ticket_type == "simple":
        id_ticket = 0
    elif ticket_type == "medium":
        id_ticket = 1
    elif ticket_type == "rare":
        id_ticket = 2
    elif ticket_type == "legendary":
        id_ticket = 3

    if id_ticket == -1:
        return False

    db_key = get_tickets(user, id_ticket)
    db_key_base64 = b64decode(db_key)

    if verify_rsa(load_rsa_public_key(), key, db_key_base64):
        print("Verificação do bilhete efetuada com sucesso!")
        return True

    print("Verificação do bilhete falhou!")
    return False
