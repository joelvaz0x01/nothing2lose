from time import time

from crypto import convert_key_to_hex, decrypt
from rsa import verify_ticket_key


def start_brute_force(encrypted_prize, ticket_type, email, aes_mode, hmac_mode):
    brute_force = brute_force_key(encrypted_prize, ticket_type, email, aes_mode, hmac_mode)
    is_decrypted = brute_force[2]
    if is_decrypted:
        print(f'\nTempo decorrido: {brute_force[3]:.2f} segundos')
        print(f'Bilhete desencriptado: {brute_force[0]}')
        print(f"Chave encontrada: {int.from_bytes(brute_force[1], 'big')}")

    return is_decrypted


def brute_force_key(encrypted_prize, ticket_type, user, mode_aes, mode_hmac):
    """
    Function that performs a brute force attack to find the key

    Returns:
    --------
    key : str
        Generated key
    """
    print("Para pausar o modo de brute-force, prima CTRL+C.\n")
    key_generated = 0
    pause_time = 0

    start_time = time()
    while True:
        try:
            key = convert_key_to_hex(key_generated)
            decrypt_result = decrypt(encrypted_prize, key, mode_aes, mode_hmac)
            if decrypt_result[2]:
                end_time = time() - start_time - pause_time
                if verify_ticket_key(key, ticket_type, user):
                    return [decrypt_result[0], decrypt_result[1], decrypt_result[2], end_time]

                return [-1, b'\x00', False, -1]  # [decrypted_data, key, is_decrypted, time]

            key_generated += 1

        except KeyboardInterrupt:
            start_time_pause = time()
            while True:
                try:
                    print("\nO que deseja fazer?")
                    print("1 - Continuar o modo de brute-force.")
                    print("3 - Sair do modo de brute-force.")
                    option = int(input("Selecione a opção desejada: "))
                    if option == 1:
                        pause_time += time() - start_time_pause
                        print("\nPara pausar o modo de brute-force, prima CRTRL+C.\n")
                        break
                    elif option == 3:
                        return [-1, b'\x00', False, -1]  # [decrypted_data, key, is_decrypted, time]
                    else:
                        print("Opção inválida. Tente novamente.")

                except ValueError:
                    print("Opção inválida. Tente novamente.")
                    continue
