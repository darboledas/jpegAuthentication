import hashlib
import sys
import os

def extract_image_data_and_hash(jpeg_path):
    with open(jpeg_path, 'rb') as f:
        data = f.read()

    # Marcadores JPEG
    SOS = b'\xFF\xDA'
    EOI = b'\xFF\xD9'

    sos_index = data.find(SOS)
    if sos_index == -1:
        raise ValueError("No se encontró el marcador SOS (0xFFDA).")

    eoi_index = data.rfind(EOI)
    if eoi_index == -1:
        raise ValueError("No se encontró el marcador EOI (0xFFD9).")

    # Leer la longitud del segmento SOS (2 bytes después del marcador)
    sos_length = int.from_bytes(data[sos_index + 2 : sos_index + 4], byteorder='big')

    # Determinar rango de datos codificados
    start = sos_index + 2 + sos_length  # salto FFDA + longitud + cabecera
    end = eoi_index  # sin incluir FFD9

    image_data = data[start:end]

    # Mostrar primeros y últimos dos bytes de la región hasheada
    first_two = image_data[:2]
    last_two = image_data[-2:]

    print(f"Primeros 2 bytes incluidos en el hash: {first_two.hex().upper()}")
    print(f"Últimos 2 bytes incluidos en el hash:  {last_two.hex().upper()}")

    # Calcular hash MD5
    md5_hash = hashlib.md5(image_data).hexdigest()
    return md5_hash

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python calcular_hash_jpeg.py <ruta_a_la_imagen.jpg>")
        sys.exit(1)

    jpeg_path = sys.argv[1]

    if not os.path.isfile(jpeg_path):
        print(f"Error: archivo no encontrado: {jpeg_path}")
        sys.exit(1)

    try:
        hash_result = extract_image_data_and_hash(jpeg_path)
        print(f"Hash MD5 entre SOS y EOI (excluyendo marcadores): {hash_result}")
    except Exception as e:
        print(f"Error al procesar la imagen: {e}")
        sys.exit(1)
