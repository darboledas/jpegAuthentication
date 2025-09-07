import hashlib
import base64
import sys
import os
from Crypto.Signature import pkcs1_15
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA
# Usage: python sign_jpeg.py <image.jpg> <IMEI> <private_key.pem> <output.jpg>

def calcular_md5_region(jpeg_data):
    SOS = b'\xFF\xDA'
    EOI = b'\xFF\xD9'

    sos_index = jpeg_data.find(SOS)
    if sos_index == -1:
        raise ValueError("SOS marker (0xFFDA) not found.")

    eoi_index = jpeg_data.rfind(EOI)
    if eoi_index == -1:
        raise ValueError("EOI marker (0xFFD9) not found.")

    # SOS segment header length
    sos_length = int.from_bytes(jpeg_data[sos_index + 2 : sos_index + 4], byteorder='big')

    start = sos_index + 2 + sos_length
    end = eoi_index

    return hashlib.md5(jpeg_data[start:end]).hexdigest()

def firmar_cadena_rsa(cadena, clave_privada_path):
    with open(clave_privada_path, 'rb') as f:
        clave_privada = RSA.import_key(f.read())

    h = MD5.new(cadena.encode('utf-8'))
    firma = pkcs1_15.new(clave_privada).sign(h)
    return base64.b64encode(firma).decode('ascii')

def insertar_bloque_com(jpeg_data, mensaje_completo):
    SOS = b'\xFF\xDA'

    sos_index = jpeg_data.find(SOS)
    if sos_index == -1:
        raise ValueError("SOS marker (0xFFDA) not found.")

    # Create COM block: FFFE + length + data
    com_payload = mensaje_completo.encode('utf-8')
    longitud = len(com_payload) + 2  # longitud includes the 2 length bytes
    bloque_com = b'\xFF\xFE' + longitud.to_bytes(2, 'big') + com_payload

    # Insert COM block before FFDA
    return jpeg_data[:sos_index] + bloque_com + jpeg_data[sos_index:]

def procesar_imagen_con_firma(jpeg_path, imei, clave_privada_path, salida_path):
    with open(jpeg_path, 'rb') as f:
        jpeg_data = f.read()

    hash_md5 = calcular_md5_region(jpeg_data)
    cadena_a_firmar = f"IMEI={imei}|MD5={hash_md5}"
    firma_b64 = firmar_cadena_rsa(cadena_a_firmar, clave_privada_path)

    mensaje_final = f"{cadena_a_firmar}|SIG={firma_b64}"
    jpeg_modificado = insertar_bloque_com(jpeg_data, mensaje_final)

    with open(salida_path, 'wb') as f:
        f.write(jpeg_modificado)

    print("COM block successfully inserted.")
    print(f"Signed chain: {mensaje_final}")

# === Command line usage ===
if __name__ == "__main__":
    if len(sys.argv) != 5:
        print("Usage: python sign_jpeg.py <image.jpg> <IMEI> <private_key.pem> <output.jpg>")
        sys.exit(1)

    jpeg_path = sys.argv[1]
    imei = sys.argv[2]
    clave_privada_path = sys.argv[3]
    salida_path = sys.argv[4]

    if not os.path.isfile(jpeg_path):
        print(f"JPEG file not found: {jpeg_path}")
        sys.exit(1)

    if not os.path.isfile(clave_privada_path):
        print(f"Private key not found: {clave_privada_path}")
        sys.exit(1)

    procesar_imagen_con_firma(jpeg_path, imei, clave_privada_path, salida_path)
