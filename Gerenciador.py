import base64
import re
import tkinter as tk
from tkinter import messagebox
from tkinter import PhotoImage
from cryptography.fernet import Fernet

def caesar_cipher(text, shift):
    result = ''
    for char in text:
        if char.isalpha():
            ascii_offset = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
        else:
            result += char
    return result

def bigraorao_encrypt(texto):
    big = ''
    for char in texto:
        
        # Converte o caractere para hexadecimal, adiciona 13 e pega os ultimos dois digitos
        big += hex((ord(char) + 13) % 256)[2:]
        
    return big

def is_hex(s):
    try:
        int(s, 16)
        return True
    except ValueError:
        return False

def bigraorao_decrypt(texto_hex):
    # Divide o texto hexadecimal em pares
    pares_hex = [texto_hex[i:i+2] for i in range(0, len(texto_hex), 2)]

    # Converte cada par hexadecimal de volta para o caractere correspondente, subtraindo 13
    big = ''.join([chr((int(par, 16) - 13) % 256) for par in pares_hex if is_hex(par)])

    return big

def generate_key():
    return Fernet.generate_key()

def encrypt_password(key, password):
    ceaser_cypher_enc = caesar_cipher(password, 13) 
    bigraorao_encrypted = bigraorao_encrypt(ceaser_cypher_enc)
    base64_encoded = base64.b64encode(bigraorao_encrypted.encode()).decode()
    f = Fernet(key)
   
    return f.encrypt(base64_encoded.encode()).decode()

def decrypt_password(key, encrypted_password):
    f = Fernet(key)
    base64_decoded = f.decrypt(encrypted_password.encode()).decode()
    # Decodificar de base64
    bigraorao_decrypted = base64.b64decode(base64_decoded.encode()).decode()
    # Aplicar a funcao bigraorao_decrypt
    caesar_decrypted = bigraorao_decrypt(bigraorao_decrypted)
    # Aplicar a cifra de Cesar inversa
    return caesar_cipher(caesar_decrypted, -13)

passwords = {}

def verify_password(password):
    if len(password) < 8:
        return False
    if not re.search("[a-z]", password):
        return False
    if not re.search("[A-Z]", password):
        return False
    if not re.search("[0-9]", password):
        return False
    if not re.search("[!@#$%^&*()]", password):
        return False
    if re.search(" ", password):
        return False
    return True

def add_password():
    service = service_entry.get()
    username = username_entry.get()
    password = password_entry.get()

    if (verify_password(password) == False):
        messagebox.showinfo("Ops!", "A sua senha deve conter ao menos 8 caracteres, dentre estes devem ter ao menos 8 números, 1 caracter maíusculo, 1 caracter minúsculo e 1 caracter especial, também não pode conter espaços!")
        return

    if service and username and password:
        encrypted_password = encrypt_password(key, password)
        passwords[service] = {'username': username, 'password': encrypted_password}
        messagebox.showinfo("Sucesso", "Sua senha foi salva com sucesso!")
    else:
        messagebox.showwarning("Erro", "Preencha adequadamente todos os campos...")

def get_password():
    service = service_entry.get()
    if service in passwords:
        encrypted_password = passwords[service]['password']
        decrypted_password = decrypt_password(key, encrypted_password)
        messagebox.showinfo("Senha", f"Usuário: {passwords[service]['username']}\nSenha: {decrypted_password}")
    else:
        messagebox.showwarning("Erro", "Não foi possível encontrar esta senha!")

key = generate_key()

instructions = '''Para adicionar uma senha preencha todos os campos e selecione "Adicionar"
Para visualizar a senha, coloque o nome da conta e selecione "Recuperar"'''
signature = "Desenvolvido por Laura Rieko e Pedro Alves para a HackoonWeek 2023"

window = tk.Tk()
window.title("Gerenciador de senhas")
window.configure(bg="#FFC30B")

#background_image = PhotoImage(file="C:\Users\laura\UFSCar\Py1\Pattern.png")
#background_label = tk.Label(window, image=background_image)
#background_label.place(x=0, y=0, relwidth=1, relheight=1)

window.resizable(False, False)


center_frame = tk.Frame(window, bg="#d3d3d3")
center_frame.grid(row=0, column=0, padx=10, pady=10)

instruction_label = tk.Label(center_frame, text=instructions, bg="#d3d3d3")
instruction_label.grid(row=0, column=1, padx=10, pady=5)

service_label = tk.Label(center_frame, text="Conta:", bg="#d3d3d3")
service_label.grid(row=1, column=0, padx=10, pady=5)
service_entry = tk.Entry(center_frame)
service_entry.grid(row=1, column=1, padx=10, pady=5)

username_label = tk.Label(center_frame, text="Usuário:", bg="#d3d3d3")
username_label.grid(row=2, column=0, padx=10, pady=5)
username_entry = tk.Entry(center_frame)
username_entry.grid(row=2, column=1, padx=10, pady=5)

password_label = tk.Label(center_frame, text="Senha:", bg="#d3d3d3")
password_label.grid(row=3, column=0, padx=10, pady=5)
password_entry = tk.Entry(center_frame, show="*")
password_entry.grid(row=3, column=1, padx=10, pady=5)


add_button = tk.Button(center_frame, text="Adicionar", command=add_password, height=1, width=10)
add_button.grid(row=5, column=4, padx=10, pady=5)

get_button = tk.Button(center_frame, text="Obter senha", command=get_password, height=1, width=10)
get_button.grid(row=6, column=4, padx=10, pady=5)

signature_label = tk.Label(center_frame, text=signature, bg="#d3d3d3")
signature_label.grid(row=7, column=1, padx=5, pady=5)


window.mainloop()
