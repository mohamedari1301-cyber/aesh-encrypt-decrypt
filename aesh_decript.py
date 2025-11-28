import os
import sys
import argparse
import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Dérive une clé de 32 octets (256 bits) à partir du mot de passe et du sel
    en utilisant PBKDF2HMAC avec SHA256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password):
    """
    Chiffre un fichier avec AES-256-GCM.
    Format du fichier chiffré : [SALT (16)][NONCE (12)][CIPHERTEXT + TAG]
    """
    if not os.path.exists(file_path):
        print(f"[-] Fichier introuvable : {file_path}")
        return

    print(f"[*] Chiffrement de '{file_path}'...")

    # Génération d'un sel aléatoire et d'un nonce
    salt = os.urandom(16)
    nonce = os.urandom(12)

    # Dérivation de la clé
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        with open(file_path, 'rb') as f:
            data = f.read()

        # Chiffrement (le tag est automatiquement ajouté à la fin par AESGCM)
        ciphertext = aesgcm.encrypt(nonce, data, None)

        out_path = file_path + ".enc"
        with open(out_path, 'wb') as f:
            f.write(salt)
            f.write(nonce)
            f.write(ciphertext)

        print(f"[+] Fichier chiffré créé : {out_path}")

        # Optionnel : Supprimer l'original ? Pour l'instant on garde par sécurité.
        # os.remove(file_path)

    except Exception as e:
        print(f"[-] Erreur lors du chiffrement : {e}")

def decrypt_file(file_path, password):
    """
    Déchiffre un fichier créé par encrypt_file.
    """
    if not os.path.exists(file_path):
        print(f"[-] Fichier introuvable : {file_path}")
        return

    if not file_path.endswith(".enc"):
        print("[-] Le fichier ne semble pas être chiffré (.enc manquant)")
        return

    print(f"[*] Déchiffrement de '{file_path}'...")

    try:
        with open(file_path, 'rb') as f:
            # Lecture du sel et du nonce
            salt = f.read(16)
            nonce = f.read(12)
            ciphertext = f.read()

        # Dérivation de la clé
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)

        # Déchiffrement
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        out_path = file_path[:-4] # Enlever .enc
        with open(out_path, 'wb') as f:
            f.write(plaintext)

        print(f"[+] Fichier déchiffré restauré : {out_path}")

    except InvalidTag:
        print("[-] Erreur : Mot de passe incorrect ou fichier corrompu.")
    except Exception as e:
        print(f"[-] Erreur lors du déchiffrement : {e}")

def main():
    parser = argparse.ArgumentParser(description="Outil de chiffrement/déchiffrement AES-256-GCM")
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Commande encrypt
    parser_enc = subparsers.add_parser('encrypt', help='Chiffrer un fichier')
    parser_enc.add_argument('file', help='Chemin du fichier à chiffrer')

    # Commande decrypt
    parser_dec = subparsers.add_parser('decrypt', help='Déchiffrer un fichier')
    parser_dec.add_argument('file', help='Chemin du fichier à déchiffrer')

    # Argument global pour le mot de passe (optionnel, pour automation)
    parser.add_argument('--password', help='Mot de passe (optionnel, sinon demandé interactivement)')

    args = parser.parse_args()

    # Gestion du mot de passe
    if args.password:
        password = args.password
    else:
        password = getpass.getpass("Entrez le mot de passe : ")

    if args.command == 'encrypt':
        encrypt_file(args.file, password)
    elif args.command == 'decrypt':
        decrypt_file(args.file, password)

if __name__ == "__main__":
    main()
