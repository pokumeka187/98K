import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import ttkbootstrap as ttkb
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import os

class FileEncryptorApp:                                    
    def __init__(self, root): 
        self.root = root
        self.root.title("98K - Шифрование файлов")
        self.root.geometry("600x700")
        self.root.resizable(False, False)
        self.file_path = None

        self.style = ttkb.Style()
        self.style.configure("Custom.TFrame", background="#344591")
        self.style.configure("Custom.TLabel", background="#344591", foreground="#FFFFFF", font=("Arial", 12))
        self.style.configure("Title.TLabel", background="#344591", foreground="#00B4D8", font=("Arial", 18, "bold"))
        self.style.configure("Subtitle.TLabel", background="#344591", foreground="#CCCCCC", font=("Arial", 10, "italic"))
        self.style.configure("Custom.TButton", font=("Arial", 11, "bold"), foreground="#FFFFFF")
        self.style.configure("Custom.TEntry", font=("Arial", 11), foreground="#FFFFFF", background="#2A2A2A")
        
        self.create_menu()
        self.create_widgets()
        self.animate_window_open()
        
    def animate_window_open(self):
        self.root.attributes('-alpha', 0.0)
        alpha = 0.0
        def fade_in():
            nonlocal alpha
            alpha += 0.05
            self.root.attributes('-alpha', alpha)
            if alpha < 1.0:
                self.root.after(20, fade_in)
        self.root.after(100, fade_in)
        
    def create_menu(self):
        menubar = tk.Menu(self.root, bg="#344591", fg="#00B4D8", activebackground="#FF2E63", activeforeground="#FFFFFF", font=("Arial", 10))
        self.root.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0, bg="#344591", fg="#00B4D8", activebackground="#FF2E63", font=("Arial", 10))
        menubar.add_cascade(label="Файл", menu=file_menu)
        file_menu.add_command(label="Выбрать файл", command=self.select_file)
        file_menu.add_command(label="Сбросить выбор", command=self.reset_selection)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.root.quit)
        
        help_menu = tk.Menu(menubar, tearoff=0, bg="#344591", fg="#00B4D8", activebackground="#FF2E63", font=("Arial", 10))
        menubar.add_cascade(label="Помощь", menu=help_menu)
        help_menu.add_command(label="Инструкция", command=self.show_help)
        help_menu.add_command(label="О программе", command=self.show_about)
        
    def create_widgets(self):
        main_frame = ttk.Frame(self.root, style="Custom.TFrame", padding=30)
        main_frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.9, relheight=0.85)
        
        title_frame = ttk.Frame(main_frame, style="Custom.TFrame")
        title_frame.pack(fill="x", pady=(0, 20))
        ttk.Label(title_frame, text="⚙️ 98K", style="Title.TLabel").pack()
        ttk.Label(title_frame, text="Универсальный шифратор файлов", style="Subtitle.TLabel").pack()
        
        separator = ttk.Separator(main_frame, orient="horizontal", bootstyle="light")
        separator.pack(fill="x", pady=10)
        
        file_frame = ttk.Frame(main_frame, style="Custom.TFrame")
        file_frame.pack(fill="x", pady=10)
        ttk.Button(file_frame, text="📂 Выбрать файл", command=self.select_file, style="Custom.TButton", 
                   bootstyle="outline", compound="left").pack(side="top", pady=5, ipadx=15, ipady=5)
        self.file_label = ttk.Label(file_frame, text="Файл не выбран", style="Custom.TLabel", wraplength=500)
        self.file_label.pack(side="top", pady=10)
        
        password_frame = ttk.Frame(main_frame, style="Custom.TFrame")
        password_frame.pack(fill="x", pady=10)
        ttk.Label(password_frame, text="💻 Пароль:", style="Custom.TLabel").pack(side="top")
        self.password_entry = ttk.Entry(password_frame, show="*", width=35, style="Custom.TEntry", bootstyle="dark")
        self.password_entry.pack(side="top", pady=5, ipady=5)
        
        button_frame = ttk.Frame(main_frame, style="Custom.TFrame")
        button_frame.pack(fill="x", pady=20)
        button_frame.grid_columnconfigure((0, 1), weight=1)
        ttk.Button(button_frame, text="🔒 Зашифровать", command=self.encrypt_file, style="Custom.TButton", 
                   bootstyle="outline", width=20).grid(row=0, column=0, padx=10, pady=5, sticky="e")
        ttk.Button(button_frame, text="🔓 Расшифровать", command=self.decrypt_file, style="Custom.TButton", 
                   bootstyle="outline", width=20).grid(row=0, column=1, padx=10, pady=5, sticky="w")
        
        separator_bottom = ttk.Separator(main_frame, orient="horizontal", bootstyle="light")
        separator_bottom.pack(fill="x", pady=10)
        
        footer_label = ttk.Label(main_frame, text="Томск - Гимназия #13", style="Subtitle.TLabel")
        footer_label.pack(pady=5)
        
    def is_encrypted(self, filepath):
        if not filepath:
            return False
        if filepath.endswith(".encrypted"):
            try:
                with open(filepath, 'rb') as f:
                    data = f.read(32)
                    if len(data) == 32:
                        return True
            except:
                return False
        return False
    
    def select_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            filename = os.path.basename(self.file_path)
            status = "Зашифрован" if self.is_encrypted(self.file_path) else "Не зашифрован"
            self.file_label.config(text=f"Выбран: {filename} ({status})")
        else:
            self.file_label.config(text="Файл не выбран")
    
    def reset_selection(self):
        self.file_path = None
        self.file_label.config(text="Файл не выбран")
        messagebox.showinfo("Успех", "Выбор файла сброшен.", parent=self.root)
    
    def get_key(self, password):
        salt = b'static_salt_for_demo'
        return PBKDF2(password.encode(), salt, dkLen=32)
    
    def encrypt_file(self):
        if not self.file_path:
            messagebox.showerror("Ошибка", "Выберите файл!", parent=self.root)
            return
        if self.is_encrypted(self.file_path):
            messagebox.showwarning("Предупреждение", "Файл уже зашифрован!", parent=self.root)
            return
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Ошибка", "Введите пароль!", parent=self.root)
            return
            
        key = self.get_key(password)
        nonce = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        
        try:
            with open(self.file_path, 'rb') as f:
                data = f.read()
            ciphertext, tag = cipher.encrypt_and_digest(data)
            
            output_path = self.file_path + ".encrypted"
            with open(output_path, 'wb') as f:
                f.write(nonce)
                f.write(tag)
                f.write(ciphertext)
            messagebox.showinfo("Успех", f"Файл зашифрован: {output_path}", parent=self.root)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось зашифровать: {str(e)}", parent=self.root)
    
    def decrypt_file(self):
        if not self.file_path:
            messagebox.showerror("Ошибка", "Выберите файл!", parent=self.root)
            return
        if not self.is_encrypted(self.file_path):
            messagebox.showwarning("Предупреждение", "Файл не зашифрован!", parent=self.root)
            return
        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Ошибка", "Введите пароль!", parent=self.root)
            return
            
        key = self.get_key(password)
        
        try:
            with open(self.file_path, 'rb') as f:
                nonce = f.read(16)
                tag = f.read(16)
                ciphertext = f.read()
            cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
            data = cipher.decrypt_and_verify(ciphertext, tag)
            
            output_path = self.file_path
            if output_path.endswith(".encrypted"):
                output_path = output_path[:-10]
            with open(output_path, 'wb') as f:
                f.write(data)
            messagebox.showinfo("Успех", f"Файл расшифрован: {output_path}", parent=self.root)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось расшифровать: {str(e)}", parent=self.root)
    
    def show_help(self):
        messagebox.showinfo("Инструкция", "1. Выберите файл через кнопку или меню.\n2. Введите пароль для шифрования/расшифровки.\n3. Нажмите 'Зашифровать' или 'Расшифровать'.\n\nВажно: Используйте одинаковый пароль для шифрования и расшифровки!", parent=self.root)
    
    def show_about(self):
        messagebox.showinfo("О программе", "98K Crypter v1.8\n\nСоздано для защиты ваших данных с помощью шифрования AES.\n\nАвтор: Евгений (Pokumeka)\n Проект ИВТ, Гимназия №13, Томск, 2025", parent=self.root)

if __name__ == "__main__":
    root = ttkb.Window(themename="darkly")
    app = FileEncryptorApp(root)
    root.mainloop()
