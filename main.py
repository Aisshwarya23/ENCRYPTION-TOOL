import tkinter as tk
from tkinter import filedialog, messagebox
from crypto_util import encrypt_file, decrypt_file

# Dark mode theme colors
BG_COLOR = "#1e1e1e"
FG_COLOR = "#ffffff"
ENTRY_BG = "#2e2e2e"
BTN_COLOR = "#007acc"
BTN_HOVER = "#005f99"

# Button hover effect
def on_enter(e):
    e.widget['background'] = BTN_HOVER

def on_leave(e):
    e.widget['background'] = BTN_COLOR

def select_file():
    path = filedialog.askopenfilename()
    filepath.set(path)

def do_encrypt():
    if not filepath.get() or not password.get():
        messagebox.showerror("Error", "Please select a file and enter a password.")
        return
    try:
        encrypt_file(filepath.get(), password.get())
        messagebox.showinfo("Success", "File encrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def do_decrypt():
    if not filepath.get() or not password.get():
        messagebox.showerror("Error", "Please select a file and enter a password.")
        return
    try:
        decrypt_file(filepath.get(), password.get())
        messagebox.showinfo("Success", "File decrypted successfully!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# --- GUI Setup ---
app = tk.Tk()
app.title("🔐 AES-256 Encryption Tool")
app.configure(bg=BG_COLOR)
app.geometry("500x300")
app.resizable(False, False)

filepath = tk.StringVar()
password = tk.StringVar()

# --- Styling ---
def label(text):
    return tk.Label(app, text=text, fg=FG_COLOR, bg=BG_COLOR, font=("Segoe UI", 10, "bold"))

def entry(var, show=None):
    return tk.Entry(app, textvariable=var, bg=ENTRY_BG, fg=FG_COLOR, insertbackground=FG_COLOR,
                    highlightthickness=1, relief="flat", show=show, font=("Segoe UI", 10))

def button(text, cmd):
    btn = tk.Button(app, text=text, command=cmd, bg=BTN_COLOR, fg="white", activebackground=BTN_HOVER,
                    font=("Segoe UI", 10, "bold"), relief="flat", padx=10, pady=5)
    btn.bind("<Enter>", on_enter)
    btn.bind("<Leave>", on_leave)
    return btn

# --- Layout ---
label("Select File:").pack(pady=(20, 5))
file_entry = entry(filepath)
file_entry.pack(ipady=3, ipadx=5, padx=20, fill='x')
tk.Button(app, text="Browse", command=select_file, bg="#444", fg="white", relief="flat").pack(pady=(5, 15))

label("Enter Password:").pack()
entry(password, show="*").pack(ipady=3, ipadx=5, padx=20, fill='x', pady=(0, 20))

button("🔐 Encrypt File", do_encrypt).pack(pady=5)
button("🔓 Decrypt File", do_decrypt).pack(pady=5)

# --- Run ---
app.mainloop()
