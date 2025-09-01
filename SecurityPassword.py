import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
import hashlib
import string
import secrets

# -----------------------------
# Función para centrar ventana
# -----------------------------
def centrar_ventana(ventana, ancho=650, alto=500):
    ventana.update_idletasks()
    screen_width = ventana.winfo_screenwidth()
    screen_height = ventana.winfo_screenheight()
    x = (screen_width // 2) - (ancho // 2)
    y = (screen_height // 2) - (alto // 2)
    ventana.geometry(f"{ancho}x{alto}+{x}+{y}")

# -----------------------------
# Función para cargar datos desde archivo JSON
# -----------------------------
def cargar_datos(archivo):
    if os.path.exists(archivo):
        try:
            with open(archivo, "r", encoding="utf-8") as file:
                return json.load(file)
        except json.JSONDecodeError:
            messagebox.showerror("Error", "El archivo de datos está corrupto o vacío.")
            return {}
    return {}

# -----------------------------
# Función para guardar datos en archivo JSON
# -----------------------------
def guardar_datos(archivo, datos):
    with open(archivo, "w", encoding="utf-8") as file:
        json.dump(datos, file, indent=4)

# -----------------------------
# Función para establecer la contraseña principal
# -----------------------------
def establecer_contrasena_principal(datos):
    nueva_contrasena = master_password_entry.get()
    if not nueva_contrasena:
        messagebox.showerror("Error", "La contraseña no puede estar vacía.")
        return
    # Guardamos la contraseña en hash SHA-256
    hash_contrasena = hashlib.sha256(nueva_contrasena.encode()).hexdigest()
    datos["contrasenha_principal"] = hash_contrasena
    guardar_datos(archivo, datos)
    messagebox.showinfo("Éxito", "Contraseña principal guardada.")
    master_password_entry.delete(0, tk.END)
    show_main_frame()

# -----------------------------
# Función para verificar la contraseña principal
# -----------------------------
def verificar_contrasena_principal(datos):
    contrasena_ingresada = master_password_entry.get()
    hash_ingresado = hashlib.sha256(contrasena_ingresada.encode()).hexdigest()
    if hash_ingresado == datos.get("contrasenha_principal"):
        show_main_frame()
    else:
        messagebox.showerror("Error", "Contraseña incorrecta.")

# -----------------------------
# Función para generar contraseña segura
# -----------------------------
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

    # Generamos la contraseña aleatoria
    return ''.join(secrets.choice(characters) for _ in range(length))

# -----------------------------
# Función para mostrar todas las contraseñas guardadas
# -----------------------------
def mostrar_contrasenas(datos):
    passwords = ""
    for k, v in datos.items():
        if k != "contrasenha_principal":
            passwords += f"{k}: {v}\n"
    messagebox.showinfo("Contraseñas Guardadas", passwords or "No hay contraseñas guardadas.")

# -----------------------------
# Función que maneja la generación y almacenamiento de contraseñas
# -----------------------------
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
        # Pregunta si ya existe la contraseña para la web
        if web in datos and not messagebox.askyesno("Sobrescribir", f"Ya existe una contraseña para {web}. ¿Deseas sobrescribirla?"):
            return
        messagebox.showinfo("Contraseña Generada", f"Tu contraseña segura es: {password}")
        # Copiamos al portapapeles
        root.clipboard_clear()
        root.clipboard_append(password)
        datos[web] = password
        guardar_datos(archivo, datos)

# -----------------------------
# Función para mostrar el frame principal
# -----------------------------
def show_main_frame():
    master_password_frame.grid_forget()
    main_frame.grid(row=0, column=0, sticky="nsew")

# -----------------------------
# Configuración inicial de la ventana
# -----------------------------
root = tk.Tk()
root.title("Gestor de Contraseñas")
centrar_ventana(root, 650, 500)
root.resizable(True, True)
root.grid_columnconfigure(0, weight=1)
root.grid_rowconfigure(0, weight=1)

archivo = "cifrado.json"
datos = cargar_datos(archivo)

# -----------------------------
# Estilos de Tkinter
# -----------------------------
style = ttk.Style()
style.configure("TButton", font=("Arial", 12), padding=6)
style.configure("TCheckbutton", font=("Arial", 12))
style.configure("TLabel", font=("Arial", 14))

# -----------------------------
# Frame de contraseña principal
# -----------------------------
master_password_frame = ttk.Frame(root, padding=30)
master_password_frame.grid(row=0, column=0, sticky="nsew")
master_password_frame.grid_columnconfigure(0, weight=1)

ttk.Label(master_password_frame, text="Introduce la contraseña principal:", anchor="center").grid(column=0, row=0, pady=20)
master_password_entry = ttk.Entry(master_password_frame, show="*", justify="center", font=("Arial", 12))
master_password_entry.grid(column=0, row=1, pady=20, sticky="ew")

if "contrasenha_principal" in datos:
    ttk.Button(master_password_frame, text="Verificar", command=lambda: verificar_contrasena_principal(datos)).grid(column=0, row=2, pady=20, sticky="ew")
else:
    ttk.Button(master_password_frame, text="Establecer", command=lambda: establecer_contrasena_principal(datos)).grid(column=0, row=2, pady=20, sticky="ew")

# -----------------------------
# Frame principal con web, longitud y opciones
# -----------------------------
main_frame = ttk.Frame(root, padding=1)
main_frame.grid_columnconfigure(0, weight=1)
for i in range(10):
    main_frame.grid_rowconfigure(i, weight=1)

# Entrada de web
ttk.Label(main_frame, text="Introduce la web:", anchor="center").grid(column=0, row=0, pady=10, sticky="ew")
web_entry = ttk.Entry(main_frame, justify="center", font=("Arial", 12))
web_entry.grid(column=0, row=1, padx=20, pady=10, sticky="ew")

# Entrada de longitud de contraseña
ttk.Label(main_frame, text="Longitud de la contraseña:", anchor="center").grid(column=0, row=2, pady=10, sticky="ew")
length_entry = ttk.Entry(main_frame, justify="center", font=("Arial", 12))
length_entry.grid(column=0, row=3, padx=20, pady=10, sticky="ew")

# Opciones de contraseña en LabelFrame
opciones_frame = ttk.LabelFrame(main_frame, text="Opciones de contraseña", padding=15)
opciones_frame.grid(column=0, row=4, pady=15, sticky="ew", padx=10)
opciones_frame.grid_columnconfigure(0, weight=1)

use_upper_var = tk.BooleanVar()
use_lower_var = tk.BooleanVar()
use_digits_var = tk.BooleanVar()
use_symbols_var = tk.BooleanVar()

ttk.Checkbutton(opciones_frame, text="Incluir mayúsculas", variable=use_upper_var).grid(column=0, row=0, sticky="w", pady=5)
ttk.Checkbutton(opciones_frame, text="Incluir minúsculas", variable=use_lower_var).grid(column=0, row=1, sticky="w", pady=5)
ttk.Checkbutton(opciones_frame, text="Incluir números", variable=use_digits_var).grid(column=0, row=2, sticky="w", pady=5)
ttk.Checkbutton(opciones_frame, text="Incluir símbolos", variable=use_symbols_var).grid(column=0, row=3, sticky="w", pady=5)

# Botones
ttk.Button(main_frame, text="Generar Contraseña", command=handle_password_generation).grid(column=0, row=5, pady=20, padx=10, sticky="ew")
ttk.Button(main_frame, text="Ver Contraseñas Guardadas", command=lambda: mostrar_contrasenas(datos)).grid(column=0, row=6, pady=10, padx=10, sticky="ew")

# -----------------------------
# Ejecutar la ventana
# -----------------------------
root.mainloop()
