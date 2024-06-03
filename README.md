# NOTHING2LOSE
> A Lottery that Compromises Time and Prizes

Final group project made for Computer Security @ [UBI - Portugal](https://www.ubi.pt/)

This project is an application to test a week security implementation in a simulated lottery system.

## Description
The idea on this project is to generate four types of tickets, each one with a different security level:
- **Level 1**: Simple ticket;
- **Level 2**: Medium ticket;
- **Level 3**: Rare ticket;
- **Level 4**: Legendary ticket.

To decrypt the tickets, the unique way is to use *brute-force* to find the correct key and decrypt the ticket.

This project has a functionality to give the user the possibility to get $1/8$ of the key if the user guesses a riddle correctly.

## Ticket Key Generation
The key must have 128 bits, because it is being used AES-128, and also must be generated randomly. For that is used the *`secrets` module* from Python.

Input:
- Encryption ticket;
- Ticket level;
- A part of the key given by the server **if riddle is guessed correctly**;
- AES mode (CBC or CTR);
- HMAC mode (SHA256 or SHA512).

Output:
- Decrypted ticket;
- Key discovered;
- If the ticket was decrypted correctly;
- Time wasted to decrypt the ticket.

## User registration
The user must register to use the application. The user must provide an **email** (used regex to validate the email), a **password** (minimum of 8 characters), and also confirms that the password entered matches the password confirmation.

## Riddle (implemented on *brute-force* functionality)
The user must guess a riddle to get 1/8 of the key to decrypt the ticket and **supposedly** has one chance to guess the riddle, but the user can try again if he/she discover a certain *bug* in the implementation of that functionality.

## RSA Signature
The server signs the ticket with an RSA key to ensure the integrity of the ticket. When the user decrypts the ticket, the user must send the ticket to the server to verify if the ticket was really found.

## Known Bugs
The user can try to guess the riddle as many times as he/she wants.

The 1/8 of the key is saved on program memory, so if the user attacks the program memory, he/she can get a fraction of the key.
