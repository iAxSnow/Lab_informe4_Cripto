# Importaciones necesarias de la librería PyCryptodome
from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import binascii # Para mostrar bytes en formato hexadecimal legible

# --- 1. Definición de detalles de algoritmos (Investigación) ---
# Esta sección corresponde a la investigación sobre tamaños de clave, IV y bloque.
# DES: key 8 bytes (64 bits, 56 efectivos), IV 8 bytes, block_size 8 bytes
# 3DES: key 16 o 24 bytes (PyCryptodome soporta ambas, usaremos 24 para mayor seguridad teórica), IV 8 bytes, block_size 8 bytes
# AES-256: key 32 bytes (256 bits), IV 16 bytes (128 bits), block_size 16 bytes

def obtener_detalles_algoritmo(nombre_algoritmo):
    """
    Retorna los parámetros (tamaño_clave_bytes, tamaño_iv_bytes, tamaño_bloque_bytes, modulo_cifrador)
    para el algoritmo especificado.
    Lanza un ValueError si el algoritmo no es soportado.
    """
    if nombre_algoritmo.upper() == "DES":
        return 8, 8, 8, DES
    elif nombre_algoritmo.upper() == "3DES":
        # Para 3DES, PyCryptodome puede usar claves de 16 o 24 bytes.
        # 16 bytes: K1, K2 (K3=K1)
        # 24 bytes: K1, K2, K3 (todas diferentes) - Ofrece mayor seguridad.
        # Optamos por 24 bytes para este laboratorio.
        return 24, 8, 8, DES3
    elif nombre_algoritmo.upper() == "AES-256":
        return 32, 16, 16, AES
    else:
        raise ValueError("Algoritmo no soportado. Por favor, elija entre DES, 3DES o AES-256.")

def ajustar_datos_entrada(datos_str, longitud_requerida_bytes, nombre_dato="Dato"):
    """
    Convierte una cadena de texto (datos_str) a bytes (usando UTF-8),
    y luego la ajusta (rellenando con bytes aleatorios o truncando)
    para que tenga la longitud_requerida_bytes.
    Imprime la clave/IV original y la ajustada en formato hexadecimal.
    Retorna los bytes ajustados.
    """
    datos_bytes = datos_str.encode('utf-8')
    longitud_actual_bytes = len(datos_bytes)

    print(f"\n--- Ajuste de {nombre_dato} ---")
    print(f"{nombre_dato} original ingresado (string): '{datos_str}'")
    print(f"{nombre_dato} original (bytes UTF-8, hex): {binascii.hexlify(datos_bytes).decode()}")
    print(f"Longitud original de {nombre_dato}: {longitud_actual_bytes} bytes. Longitud requerida: {longitud_requerida_bytes} bytes.")

    if longitud_actual_bytes < longitud_requerida_bytes:
        bytes_faltantes = longitud_requerida_bytes - longitud_actual_bytes
        relleno_aleatorio = get_random_bytes(bytes_faltantes)
        datos_ajustados_bytes = datos_bytes + relleno_aleatorio
        print(f"Se completó {nombre_dato} con {bytes_faltantes} byte(s) aleatorio(s).")
    elif longitud_actual_bytes > longitud_requerida_bytes:
        datos_ajustados_bytes = datos_bytes[:longitud_requerida_bytes]
        print(f"Se truncó {nombre_dato} a {longitud_requerida_bytes} bytes.")
    else:
        datos_ajustados_bytes = datos_bytes
        print(f"{nombre_dato} ya tiene la longitud correcta.")
    
    print(f"{nombre_dato} final utilizado (hex): {binascii.hexlify(datos_ajustados_bytes).decode()}")
    return datos_ajustados_bytes

def cifrar_datos(modulo_cifrador, clave, iv, texto_plano_bytes, tamaño_bloque_bytes):
    """
    Cifra texto_plano_bytes usando el algoritmo, clave, IV y modo CBC.
    Aplica padding PKCS#7 antes de cifrar.
    Retorna el texto cifrado en bytes.
    """
    # Crear un nuevo objeto cifrador en modo CBC
    cifrador = modulo_cifrador.new(clave, modulo_cifrador.MODE_CBC, iv)
    
    # Aplicar padding PKCS#7 al texto plano para que sea múltiplo del tamaño de bloque
    texto_plano_con_padding = pad(texto_plano_bytes, tamaño_bloque_bytes)
    
    # Cifrar
    texto_cifrado_bytes = cifrador.encrypt(texto_plano_con_padding)
    return texto_cifrado_bytes

def descifrar_datos(modulo_cifrador, clave, iv, texto_cifrado_bytes, tamaño_bloque_bytes):
    """
    Descifra texto_cifrado_bytes usando el algoritmo, clave, IV y modo CBC.
    Elimina el padding PKCS#7 después de descifrar.
    Retorna el texto plano original en bytes, o None si hay error en unpadding.
    """
    # Crear un nuevo objeto cifrador en modo CBC para descifrar
    descifrador = modulo_cifrador.new(clave, modulo_cifrador.MODE_CBC, iv)
    
    # Descifrar
    texto_descifrado_con_padding_bytes = descifrador.decrypt(texto_cifrado_bytes)
    
    # Eliminar el padding PKCS#7
    try:
        texto_plano_bytes = unpad(texto_descifrado_con_padding_bytes, tamaño_bloque_bytes)
        return texto_plano_bytes
    except ValueError:
        # Esto puede ocurrir si la clave/IV es incorrecta, los datos están corruptos,
        # o el padding no es válido.
        print("Error: No se pudo quitar el padding. Verifique la clave, el IV o la integridad del texto cifrado.")
        return None

def main():
    print("=" * 50)
    print("INFORME LABORATORIO 4: CIFRADO SIMÉTRICO")
    print("=" * 50)

    # --- 2. Solicitar datos de entrada desde la terminal ---
    while True:
        print("\nAlgoritmos disponibles: DES, 3DES, AES-256")
        algoritmo_elegido_str = input("Seleccione el algoritmo a utilizar: ").strip()
        try:
            tamaño_clave, tamaño_iv, tamaño_bloque, modulo_cifrador = obtener_detalles_algoritmo(algoritmo_elegido_str)
            print(f"Algoritmo seleccionado: {algoritmo_elegido_str.upper()}")
            print(f"  Tamaño de clave requerido: {tamaño_clave} bytes")
            print(f"  Tamaño de IV requerido: {tamaño_iv} bytes")
            print(f"  Tamaño de bloque: {tamaño_bloque} bytes")
            break
        except ValueError as e:
            print(f"Error: {e}")

    clave_str_usuario = input("Ingrese la Key (cadena de texto): ")
    iv_str_usuario = input("Ingrese el Vector de Inicialización (IV) (cadena de texto): ")
    texto_plano_str_usuario = input("Ingrese el texto a cifrar: ")
    texto_plano_bytes_original = texto_plano_str_usuario.encode('utf-8')

    # --- 3. Validación y ajuste de la clave e IV ---
    clave_final_bytes = ajustar_datos_entrada(clave_str_usuario, tamaño_clave, "Key")
    iv_final_bytes = ajustar_datos_entrada(iv_str_usuario, tamaño_iv, "IV")

    # --- 4. Cifrado y Descifrado ---
    print("\n--- Proceso de Cifrado ---")
    print(f"Texto plano original (string): '{texto_plano_str_usuario}'")
    print(f"Texto plano original (bytes UTF-8, hex): {binascii.hexlify(texto_plano_bytes_original).decode()}")

    texto_cifrado = cifrar_datos(modulo_cifrador, clave_final_bytes, iv_final_bytes, texto_plano_bytes_original, tamaño_bloque)
    print(f"Texto Cifrado (hex): {binascii.hexlify(texto_cifrado).decode()}")

    print("\n--- Proceso de Descifrado ---")
    texto_descifrado_bytes = descifrar_datos(modulo_cifrador, clave_final_bytes, iv_final_bytes, texto_cifrado, tamaño_bloque)

    if texto_descifrado_bytes is not None:
        texto_descifrado_str = texto_descifrado_bytes.decode('utf-8')
        print(f"Texto Descifrado (string): '{texto_descifrado_str}'")
        print(f"Texto Descifrado (bytes UTF-8, hex): {binascii.hexlify(texto_descifrado_bytes).decode()}")

        # Verificación final
        if texto_descifrado_bytes == texto_plano_bytes_original:
            print("\n¡ÉXITO! El texto descifrado coincide con el texto plano original.")
        else:
            print("\n¡ERROR! El texto descifrado NO coincide con el texto plano original.")
    else:
        print("El proceso de descifrado falló.")
        
    print("\n" + "=" * 50)
    print("Fin del programa.")
    print("=" * 50)

if __name__ == "__main__":
    main()
