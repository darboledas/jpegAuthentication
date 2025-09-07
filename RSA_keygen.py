# !/usr/bin/python3
# RSA_keygen.py
# David Arboledas 
# July 2024
# usage: python RSA_keygen.py <bitslenght>
# --------------------------------------------
# The script generates a public and private
# RSA key pair of the desired length.
# Only 1024, 2048 and 4096 bits are possible
# --------------------------------------------

import sys
from Crypto.PublicKey import RSA

VALID_KEY_LENGTHS = [1024, 2048, 4096]

def generate_key(length):
    print(f"[*] Generando par de claves RSA de {length} bits...")

    key = RSA.generate(length)

    private_key = key.export_key()
    public_key = key.publickey().export_key()

    try:
        with open("private.pem", "wb") as priv_file:
            priv_file.write(private_key)
        print(" [+] Clave privada escrita en 'private.pem'")
    except IOError:
        print(" [!] Error: no se pudo crear el archivo 'private.pem'")

    try:
        with open("public.pem", "wb") as pub_file:
            pub_file.write(public_key)
        print(" [+] Clave pública escrita en 'public.pem'")
    except IOError:
        print(" [!] Error: no se pudo crear el archivo 'public.pem'")

def main():
    try:
        length = int(sys.argv[1])
        if length in VALID_KEY_LENGTHS:
            generate_key(length)
        else:
            print(f"[!] Longitud no válida. Usa una de: {VALID_KEY_LENGTHS}")
    except (IndexError, ValueError):
        print("Uso: python RSA_keygen.py <tamaño_en_bits>")
        print(f"Ejemplo: python RSA_keygen.py 2048")

if __name__ == "__main__":
    main()
