from tkinter import ttk
import zipfile
import rarfile
import itertools
import string
import time
import concurrent.futures
import tkinter as tk
from tkinter import filedialog, messagebox
import threading
import customtkinter as ctk
import queue

class PasswordCrackerGUI:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("Advanced ZIP & RAR Password Cracker")
        self.root.geometry("900x600")
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        
        self.use_letters = ctk.BooleanVar(value=True)
        self.use_digits = ctk.BooleanVar(value=True)
        self.use_special = ctk.BooleanVar(value=False)
        self.update_queue = queue.Queue()
        self.running = False
        
        self.create_notebook()
        self.create_main_tab()
        self.create_settings_tab()
        self.start_queue_handler()
    def start_queue_handler(self):
        def update_gui():
            try:
                while True:
                    update_func = self.update_queue.get_nowait()
                    update_func()
            except queue.Empty:
                pass
            if self.running:
                self.root.after(100, update_gui)
        
        self.running = True
        self.root.after(100, update_gui)

    def safe_update(self, update_func):
        self.update_queue.put(update_func)

    def update_thread_label(self, value):
        self.thread_label.configure(text=f"Threads: {int(value)}")

    def get_charset(self):
        charset = ""
        if self.use_letters.get():
            charset += string.ascii_letters
        if self.use_digits.get():
            charset += string.digits
        if self.use_special.get():
            charset += string.punctuation
        return charset if charset else string.ascii_lowercase

    def browse_file(self):
        filename = filedialog.askopenfilename(filetypes=[("ZIP/RAR files", "*.zip *.rar")])
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, filename)

    def browse_wordlist(self):
        filename = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        self.wordlist_entry.delete(0, tk.END)
        self.wordlist_entry.insert(0, filename)

    def try_extract(self, file_path, password):
        try:
            if file_path.endswith(".zip"):
                with zipfile.ZipFile(file_path) as zf:
                    zf.extractall(pwd=password.encode())
            elif file_path.endswith(".rar"):
                with rarfile.RarFile(file_path) as rf:
                    rf.extractall(pwd=password)
            self.safe_update(lambda: self.status_label.configure(text=f"Password Found: {password}"))
            return password
        except:
            return None

    def brute_force_attack(self, file_path, charset, min_length, max_length, threads):
        def attack_task():
            total_attempts = sum(len(charset) ** i for i in range(min_length, max_length + 1))
            attempt_counter = 0

            def password_generator():
                for length in range(min_length, max_length + 1):
                    for attempt in itertools.product(charset, repeat=length):
                        yield "".join(attempt)

            def try_password(password):
                nonlocal attempt_counter
                result = self.try_extract(file_path, password)
                attempt_counter += 1
                if attempt_counter % 100 == 0:
                    self.safe_update(lambda: self.progress_bar.set(attempt_counter / total_attempts))
                return result

            with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
                for result in executor.map(try_password, password_generator()):
                    if result:
                        return

            self.safe_update(lambda: self.status_label.configure(text="Password not found"))

        threading.Thread(target=attack_task, daemon=True).start()

    def dictionary_attack(self, file_path, wordlist):
        def attack_task():
            with open(wordlist, "r", encoding="utf-8") as f:
                passwords = [line.strip() for line in f]
            
            total_attempts = len(passwords)
            for i, password in enumerate(passwords, 1):
                if self.try_extract(file_path, password):
                    return
                if i % 100 == 0:
                    self.safe_update(lambda: self.progress_bar.set(i / total_attempts))
            
            self.safe_update(lambda: self.status_label.configure(text="Password not found"))

        threading.Thread(target=attack_task, daemon=True).start()

    def start_attack(self):
        file_path = self.file_entry.get()
        if not file_path:
            messagebox.showerror("Error", "Please select a ZIP or RAR file.")
            return

        self.progress_bar.set(0)
        self.status_label.configure(text="Running...")

        if self.attack_var.get() == "dictionary":
            wordlist = self.wordlist_entry.get()
            if not wordlist:
                messagebox.showerror("Error", "Please select a dictionary file.")
                return
            self.dictionary_attack(file_path, wordlist)
        else:
            charset = self.get_charset()
            min_len = int(self.min_length.get())
            max_len = int(self.max_length.get())
            threads = int(self.thread_slider.get())
            self.brute_force_attack(file_path, charset, min_len, max_len, threads)

    def create_notebook(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.main_tab = ctk.CTkFrame(self.notebook)
        self.settings_tab = ctk.CTkFrame(self.notebook)
        
        self.notebook.add(self.main_tab, text='Main')
        self.notebook.add(self.settings_tab, text='Settings')

    def create_main_tab(self):
        file_frame = ctk.CTkFrame(self.main_tab)
        file_frame.pack(fill="x", padx=10, pady=5)
        
        self.file_entry = ctk.CTkEntry(file_frame, placeholder_text="Select ZIP/RAR file...", width=600)
        self.file_entry.pack(side="left", padx=5)
        
        browse_btn = ctk.CTkButton(file_frame, text="Browse", command=self.browse_file)
        browse_btn.pack(side="left", padx=5)

        mode_frame = ctk.CTkFrame(self.main_tab)
        mode_frame.pack(fill="x", padx=10, pady=5)
        
        self.attack_var = ctk.StringVar(value="dictionary")
        dict_radio = ctk.CTkRadioButton(mode_frame, text="Dictionary Attack", 
                                      variable=self.attack_var, value="dictionary")
        dict_radio.pack(side="left", padx=20)
        
        brute_radio = ctk.CTkRadioButton(mode_frame, text="Brute-Force Attack", 
                                        variable=self.attack_var, value="bruteforce")
        brute_radio.pack(side="left", padx=20)

        dict_frame = ctk.CTkFrame(self.main_tab)
        dict_frame.pack(fill="x", padx=10, pady=5)
        
        self.wordlist_entry = ctk.CTkEntry(dict_frame, placeholder_text="Select dictionary file...", width=600)
        self.wordlist_entry.pack(side="left", padx=5)
        
        dict_browse_btn = ctk.CTkButton(dict_frame, text="Browse", command=self.browse_wordlist)
        dict_browse_btn.pack(side="left", padx=5)

        self.start_btn = ctk.CTkButton(self.main_tab, text="Start Attack", 
                                      command=self.start_attack, width=200, height=40)
        self.start_btn.pack(pady=20)

        self.progress_bar = ctk.CTkProgressBar(self.main_tab, width=700)
        self.progress_bar.pack(pady=10)
        self.progress_bar.set(0)

        self.status_label = ctk.CTkLabel(self.main_tab, text="Ready")
        self.status_label.pack(pady=5)

    def create_settings_tab(self):
        charset_frame = ctk.CTkFrame(self.settings_tab)
        charset_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(charset_frame, text="Character Set Options").pack(pady=5)
        
        ctk.CTkCheckBox(charset_frame, text="Letters (a-zA-Z)", 
                       variable=self.use_letters).pack(pady=2)
        ctk.CTkCheckBox(charset_frame, text="Digits (0-9)", 
                       variable=self.use_digits).pack(pady=2)
        ctk.CTkCheckBox(charset_frame, text="Special Characters", 
                       variable=self.use_special).pack(pady=2)

        thread_frame = ctk.CTkFrame(self.settings_tab)
        thread_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(thread_frame, text="Thread Settings").pack(pady=5)
        
        self.thread_slider = ctk.CTkSlider(thread_frame, from_=1, to=16, 
                                          number_of_steps=15)
        self.thread_slider.pack(pady=5)
        self.thread_slider.set(4)
        
        self.thread_label = ctk.CTkLabel(thread_frame, text="Threads: 4")
        self.thread_label.pack()

        length_frame = ctk.CTkFrame(self.settings_tab)
        length_frame.pack(fill="x", padx=10, pady=5)
        
        ctk.CTkLabel(length_frame, text="Password Length Settings").pack(pady=5)
        
        min_frame = ctk.CTkFrame(length_frame)
        min_frame.pack(fill="x", pady=2)
        ctk.CTkLabel(min_frame, text="Min Length:").pack(side="left", padx=5)
        self.min_length = ctk.CTkEntry(min_frame, width=70)
        self.min_length.pack(side="left")
        self.min_length.insert(0, "1")
        
        max_frame = ctk.CTkFrame(length_frame)
        max_frame.pack(fill="x", pady=2)
        ctk.CTkLabel(max_frame, text="Max Length:").pack(side="left", padx=5)
        self.max_length = ctk.CTkEntry(max_frame, width=70)
        self.max_length.pack(side="left")
        self.max_length.insert(0, "8")

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = PasswordCrackerGUI()
    app.run()
