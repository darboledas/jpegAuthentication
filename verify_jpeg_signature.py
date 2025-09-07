import hashlib
import base64
import sys
import os
from Crypto.Signature import pkcs1_15
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA

def extraer_bloque_com(jpeg_data):
    i = 0
    bloques = []

    while i < len(jpeg_data) - 1:
        if jpeg_data[i] == 0xFF and jpeg_data[i + 1] == 0xFE:  # COM marker
            length = int.from_bytes(jpeg_data[i+2:i+4], byteorder='big')
            start = i + 4
            end = start + length - 2
            try:
                texto = jpeg_data[start:end].decode('utf-8')
                bloques.append(texto)
            except UnicodeDecodeError:
                pass
            i = end
        else:
            i += 1

    if not bloques:
        raise ValueError("No valid COM block found.")

    for b in bloques:
        if "IMEI=" in b and "MD5=" in b and "SIG=" in b:
            return b

    raise ValueError("COM blocks were found, but none with the expected structure.")

def calcular_md5_region(jpeg_data):
    SOS = b'\xFF\xDA'
    EOI = b'\xFF\xD9'

    sos_index = jpeg_data.find(SOS)
    if sos_index == -1:
        raise ValueError("SOS marker (0xFFDA) not found.")

    eoi_index = jpeg_data.rfind(EOI)
    if eoi_index == -1:
        raise ValueError("EOI marker (0xFFD9) not found.")

    sos_length = int.from_bytes(jpeg_data[sos_index + 2 : sos_index + 4], byteorder='big')
    start = sos_index + 2 + sos_length
    end = eoi_index

    return hashlib.md5(jpeg_data[start:end]).hexdigest()

def verificar_firma(cadena_firmada, firma_b64, clave_publica_path):
    with open(clave_publica_path, 'rb') as f:
        clave_publica = RSA.import_key(f.read())

    h = MD5.new(cadena_firmada.encode('utf-8'))
    firma = base64.b64decode(firma_b64)

    try:
        pkcs1_15.new(clave_publica).verify(h, firma)
        return True
    except (ValueError, TypeError):
        return False

def main():
    if len(sys.argv) != 3:
        print("Usage: python verify_jpeg_signature.py <image.jpg> <public_key.pem>")
        sys.exit(1)

    ruta_jpeg = sys.argv[1]
    ruta_clave_pub = sys.argv[2]

    if not os.path.isfile(ruta_jpeg):
        print(f"JPEG file not found: {ruta_jpeg}")
        sys.exit(1)

    if not os.path.isfile(ruta_clave_pub):
        print(f"Public key not found: {ruta_clave_pub}")
        sys.exit(1)

    with open(ruta_jpeg, 'rb') as f:
        jpeg_data = f.read()

    mensaje_completo = extraer_bloque_com(jpeg_data)
    print(f"Extracted COM block:\n{mensaje_completo}\n")

    partes = mensaje_completo.strip().split('|')
    datos = {}
    for parte in partes:
        if '=' in parte:
            k, v = parte.split('=', 1)
            datos[k] = v

    imei = datos.get("IMEI")
    hash_en_com = datos.get("MD5")
    firma_b64 = datos.get("SIG")

    if not all([imei, hash_en_com, firma_b64]):
        print("ERROR: Invalid COM block format.")
        sys.exit(1)

    hash_calculado = calcular_md5_region(jpeg_data)
    cadena_a_verificar = f"IMEI={imei}|MD5={hash_en_com}"

    print(f"Reported IMEI: {imei}")
    print(f"MD5 stored in COM:    {hash_en_com}")
    print(f"Computed MD5:     {hash_calculado}")

    if hash_en_com != hash_calculado:
        print("\n❌ ERROR: MD5 hash mismatch with actual image content.")
        sys.exit(1)

    if verificar_firma(cadena_a_verificar, firma_b64, ruta_clave_pub):
        print("\n✅ VALID SIGNATURE: The image is authentic and corresponds to the specified IMEI.")
    else:
        print("\n❌ INVALID SIGNATURE: The content may have been altered or the public key is not valid.")

if __name__ == "__main__":
    main()
