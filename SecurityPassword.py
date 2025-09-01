import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
import hashlib
import string
import secrets

# Cargar datos desde archivo
def cargar_datos(archivo):
    if os.path.exists(archivo):
        try:
            with open(archivo, "r", encoding="utf-8") as file:
                return json.load(file)
        except json.JSONDecodeError:
            messagebox.showerror("Error", "El archivo de datos está corrupto o vacío.")
            return {}
    return {}

# Guardar datos en archivo
def guardar_datos(archivo, datos):
    with open(archivo, "w", encoding="utf-8") as file:
        json.dump(datos, file, indent=4)

# Establecer contraseña principal
def establecer_contrasena_principal(datos):
    nueva_contrasena = master_password_entry.get()
    if not nueva_contrasena:
        messagebox.showerror("Error", "La contraseña no puede estar vacía.")
        return
    hash_contrasena = hashlib.sha256(nueva_contrasena.encode()).hexdigest()
    datos["contrasenha_principal"] = hash_contrasena
    guardar_datos(archivo, datos)
    messagebox.showinfo("Éxito", "Contraseña principal guardada.")
    master_password_entry.delete(0, tk.END)
    show_main_frame()

# Verificar contraseña principal
def verificar_contrasena_principal(datos):
    contrasena_ingresada = master_password_entry.get()
    hash_ingresado = hashlib.sha256(contrasena_ingresada.encode()).hexdigest()
    if hash_ingresado == datos.get("contrasenha_principal"):
        show_main_frame()
    else:
        messagebox.showerror("Error", "Contraseña incorrecta.")

# Generar contraseña segura
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
        messagebox.showerror("Error", "Debes seleccionar al menos un tipo de carácter.")
        return None

    return ''.join(secrets.choice(characters) for _ in range(length))

# Mostrar contraseñas guardadas
def mostrar_contrasenas(datos):
    passwords = ""
    for k, v in datos.items():
        if k != "contrasenha_principal":
            passwords += f"{k}: {v}\n"
    messagebox.showinfo("Contraseñas Guardadas", passwords or "No hay contraseñas guardadas.")

# Generar y guardar contraseña
def handle_password_generation():
    web = web_entry.get().strip()
    if not web:
        messagebox.showerror("Error", "Debes introducir un nombre para la web.")
        return

    try:
        length = int(length_entry.get())
        if length < 4:
            messagebox.showerror("Error", "La longitud debe ser al menos 4.")
            return
    except ValueError:
        messagebox.showerror("Error", "Por favor, introduce un número válido.")
        return

    use_may = use_upper_var.get()
    use_min = use_lower_var.get()
    use_digi = use_digits_var.get()
    use_simb = use_symbols_var.get()

    password = generar_contrasena(length, use_may, use_min, use_digi, use_simb)
    if password:
        if web in datos and not messagebox.askyesno("Sobrescribir", f"Ya existe una contraseña para {web}. ¿Deseas sobrescribirla?"):
            return
        messagebox.showinfo("Contraseña Generada", f"Tu contraseña segura es: {password}")
        root.clipboard_clear()
        root.clipboard_append(password)
        datos[web] = password
        guardar_datos(archivo, datos)

# Mostrar interfaz principal
def show_main_frame():
    master_password_frame.grid_forget()
    main_frame.grid()

# Configuración inicial
root = tk.Tk()
root.title("Gestor de Contraseñas")  # cambiado para no confundir con BitLocker

archivo = "cifrado.json"
datos = cargar_datos(archivo)

# Frame para contraseña principal
master_password_frame = ttk.Frame(root, padding=10)
master_password_frame.grid()

ttk.Label(master_password_frame, text="Introduce la contraseña principal:").grid(column=0, row=0, columnspan=2, sticky="w")
master_password_entry = ttk.Entry(master_password_frame, show="*")
master_password_entry.grid(column=0, row=1, columnspan=2, pady=5)

if "contrasenha_principal" in datos:
    ttk.Button(master_password_frame, text="Verificar", command=lambda: verificar_contrasena_principal(datos)).grid(column=0, row=2, pady=5)
else:
    ttk.Button(master_password_frame, text="Establecer", command=lambda: establecer_contrasena_principal(datos)).grid(column=0, row=2, pady=5)

# Frame principal
main_frame = ttk.Frame(root, padding=10)

ttk.Label(main_frame, text="Introduce la web:").grid(column=0, row=0, sticky="w")
web_entry = ttk.Entry(main_frame)
web_entry.grid(column=1, row=0, padx=5, pady=5)

ttk.Label(main_frame, text="Longitud de la contraseña:").grid(column=0, row=1, sticky="w")
length_entry = ttk.Entry(main_frame)
length_entry.grid(column=1, row=1, padx=5, pady=5)

use_upper_var = tk.BooleanVar()
use_lower_var = tk.BooleanVar()
use_digits_var = tk.BooleanVar()
use_symbols_var = tk.BooleanVar()

ttk.Checkbutton(main_frame, text="Incluir mayúsculas", variable=use_upper_var).grid(column=0, row=2, columnspan=2, sticky="w")
ttk.Checkbutton(main_frame, text="Incluir minúsculas", variable=use_lower_var).grid(column=0, row=3, columnspan=2, sticky="w")
ttk.Checkbutton(main_frame, text="Incluir números", variable=use_digits_var).grid(column=0, row=4, columnspan=2, sticky="w")
ttk.Checkbutton(main_frame, text="Incluir símbolos", variable=use_symbols_var).grid(column=0, row=5, columnspan=2, sticky="w")

ttk.Button(main_frame, text="Generar Contraseña", command=handle_password_generation).grid(column=0, row=6, columnspan=2, pady=5)
ttk.Button(main_frame, text="Ver Contraseñas Guardadas", command=lambda: mostrar_contrasenas(datos)).grid(column=0, row=7, columnspan=2, pady=5)

root.mainloop()
