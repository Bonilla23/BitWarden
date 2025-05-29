import random
import string
import json
import os
import hashlib
import getpass

# Cargar los datos del archivo
def cargar_datos(archivo):
    if os.path.exists(archivo):
        with open(archivo, "r", encoding="utf-8") as file:
            return json.load(file)
    return {}

# Guardar los datos del archivo
def guardar_datos(archivo, datos):
    with open(archivo, "w", encoding="utf-8") as file:
        json.dump(datos, file, indent=4)

# Establecer la contraseña principal con seguridad incluida y guardarla
def establecer_contrasena_principal(datos):
    nueva_contrasena = getpass.getpass("No hay contraseña principal establecida. Crea una: ")
    hash_contrasena = hashlib.sha256(nueva_contrasena.encode()).hexdigest()
    datos["contrasenha_principal"] = hash_contrasena
    print("Contraseña principal guardada.")
    return datos

# Verificar la contraseña
def verificar_contrasena_principal(datos):
    contrasena_ingresada = getpass.getpass("Introduce la contraseña principal: ")
    hash_ingresado = hashlib.sha256(contrasena_ingresada.encode()).hexdigest()
    return hash_ingresado == datos.get("contrasenha_principal")

# Mostrar contraseña y la web
def mostrar_contrasenas(datos):
    for k, v in datos.items():
        if k != "contrasenha_principal":
            print(f"{k}: {v}")

# Generamos la contraseña con lo que nos pide
def generar_contrasena(length, use_upper, use_lower, use_digits, use_symbols):
    characters = ""
    if use_upper:
        characters += string.ascii_uppercase
    if use_lower:
        characters += string.ascii_lowercase
    if use_digits:
        characters += string.digits
    if use_symbols:
        characters += string.punctuation

    if not characters:
        print("Debes seleccionar al menos un tipo de carácter.")
        return None

    return ''.join(random.choice(characters) for _ in range(length))

# Comprobar contraseña y ejecutar el resto de comandos si es correcta
def contrasenha_principal():
    archivo = "cifrado.json"
    datos = cargar_datos(archivo)

    if "contrasenha_principal" in datos:
        if not verificar_contrasena_principal(datos):
            print("Contraseña incorrecta...")
            return
    else:
        datos = establecer_contrasena_principal(datos)
        guardar_datos(archivo, datos)
        return

    verdatos = input("¿Desea ver las contraseñas? (s/n): ").lower()
    if verdatos == "s":
        mostrar_contrasenas(datos)

    web = input("Introduce la web: ")
    try:
        length = int(input("¿Longitud de la contraseña? "))
        if length < 4:
            print("La longitud debe ser al menos 4.")
            return
    except ValueError:
        print("Por favor, introduce un número válido.")
        return

    use_may = input("¿Incluir mayúsculas? (s/n): ").lower() == 's'
    use_min = input("¿Incluir minúsculas? (s/n): ").lower() == 's'
    use_digi = input("¿Incluir números? (s/n): ").lower() == 's'
    use_simb = input("¿Incluir símbolos? (s/n): ").lower() == 's'

    # Generamos la contraseña de la web con los datos que nos pidio
    password = generar_contrasena(length, use_may, use_min, use_digi, use_simb)
    if password:
        print("Tu contraseña segura es:", password)
        datos[web] = password
        guardar_datos(archivo, datos)

# Para que se ejecute de primero
if __name__ == "__main__":
    contrasenha_principal()
