import tkinter as tk
from tkinter import messagebox, ttk, simpledialog, Menu
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import threading

def pad(text):
    while len(text) % 16 != 0:
        text += ' '
    return text
#use 
# Function to unpad the plaintext
def unpad(text):
    return text.rstrip()

# Function to encrypt the message
def encrypt_message():
    key_size = int(key_size_var.get())
    key = key_entry.get().encode('utf-8')
    mode = mode_var.get()
    
    if len(key) != key_size:
        messagebox.showerror("Error", f"Key must be {key_size} bytes long.")
        return

    def worker():
        try:
            message = pad(message_entry.get("1.0", tk.END).strip()).encode('utf-8')
            
            if mode == "EAX":
                cipher = AES.new(key, AES.MODE_EAX)
                nonce = cipher.nonce
                ciphertext, tag = cipher.encrypt_and_digest(message)
                encrypted_message = base64.b64encode(nonce + tag + ciphertext).decode('utf-8')
            elif mode == "CBC":
                cipher = AES.new(key, AES.MODE_CBC, iv=get_random_bytes(16))
                ciphertext = cipher.encrypt(message)
                encrypted_message = base64.b64encode(cipher.iv + ciphertext).decode('utf-8')
            
            encrypted_result_entry.delete(0, tk.END)
            encrypted_result_entry.insert(0, encrypted_message)
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
        finally:
            progress_bar.stop()
            status_label.config(text="Encryption completed")

    status_label.config(text="Encrypting...")
    progress_bar.start()
    threading.Thread(target=worker).start()

# Function to decrypt the message
def decrypt_message():
    key_size = int(key_size_var.get())
    key = key_entry.get().encode('utf-8')
    mode = mode_var.get()
    
    if len(key) != key_size:
        messagebox.showerror("Error", f"Key must be {key_size} bytes long.")
        return

    def worker():
        try:
            encrypted_message = base64.b64decode(encrypted_result_entry.get())
            
            if mode == "EAX":
                nonce = encrypted_message[:16]
                tag = encrypted_message[16:32]
                ciphertext = encrypted_message[32:]
                cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
                decrypted_message = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
            elif mode == "CBC":
                iv = encrypted_message[:16]
                ciphertext = encrypted_message[16:]
                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                decrypted_message = unpad(cipher.decrypt(ciphertext)).decode('utf-8')
            
            decrypted_result_entry.delete(0, tk.END)
            decrypted_result_entry.insert(0, decrypted_message)
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
        finally:
            progress_bar.stop()
            status_label.config(text="Decryption completed")

    status_label.config(text="Decrypting...")
    progress_bar.start()
    threading.Thread(target=worker).start()

# Function to save the encrypted message to a file
def save_encrypted_message():
    encrypted_message = encrypted_result_entry.get()
    if not encrypted_message:
        messagebox.showwarning("Warning", "No encrypted message to save.")
        return
    filename = simpledialog.askstring("Save File", "Enter filename (e.g., encrypted_message.txt):")
    if filename:
        with open(filename, 'w') as file:
            file.write(encrypted_message)
        messagebox.showinfo("Saved", f"Encrypted message saved to {filename}")

# Function to load an encrypted message from a file
def load_encrypted_message():
    filename = simpledialog.askstring("Load File", "Enter filename (e.g., encrypted_message.txt):")
    if filename:
        try:
            with open(filename, 'r') as file:
                encrypted_message = file.read()
                encrypted_result_entry.delete(0, tk.END)
                encrypted_result_entry.insert(0, encrypted_message)
        except FileNotFoundError:
            messagebox.showerror("Error", "File not found.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load file: {str(e)}")

# Function to display the procedure in a new window
def show_procedure():
    procedure_window = tk.Toplevel(root)
    procedure_window.title("Usage Instructions")
    
    # Instructions text
    instructions = (
        "Welcome to the Advanced Encryption and Decryption Tool!\n\n"
        "This tool allows you to encrypt and decrypt messages using AES encryption. Here is how to use it:\n\n"
        "1. Select the key size from the dropdown menu. The key size can be 16, 24, 32, or 64 bytes.\n"
        "2. Enter the key in the 'Key' field. Ensure that the key length matches the selected key size.\n"
        "3. Choose the encryption mode from the dropdown menu (EAX or CBC).\n"
        "4. Enter the message you want to encrypt in the 'Message' field.\n"
        "5. Click the 'Encrypt' button to encrypt the message. The result will be displayed in the 'Encrypted Result' field.\n"
        "6. To decrypt a message, paste the encrypted message into the 'Encrypted Result' field and click the 'Decrypt' button.\n"
        "7. The decrypted message will be displayed in the 'Decrypted Result' field.\n\n"
        "Additional Features:\n"
        "- You can save the encrypted message to a file using the 'Save Encrypted Message' button.\n"
        "- Load an encrypted message from a file using the 'Load Encrypted Message' button.\n\n"
        "If you encounter any issues, please ensure that the key length matches the selected key size and that the encryption/decryption mode is correctly selected."
    )
    
    # Create and place the label with instructions
    instructions_label = tk.Label(procedure_window, text=instructions, padx=10, pady=10, justify="left", wraplength=400)
    instructions_label.pack(expand=True, fill='both')

# Create the main window
root = tk.Tk()
root.title("Advanced Encryption and Decryption")

# Create a menu bar
menu_bar = Menu(root)
root.config(menu=menu_bar)

# Create Help menu
help_menu = Menu(menu_bar, tearoff=0)
menu_bar.add_cascade(label="Help", menu=help_menu)
help_menu.add_command(label="Procedure", command=show_procedure)

# Create main frame
main_frame = tk.Frame(root, padx=10, pady=10)
main_frame.pack(fill='both', expand=True)

# Configure grid weights
main_frame.grid_rowconfigure(0, weight=1)
main_frame.grid_rowconfigure(1, weight=1)
main_frame.grid_rowconfigure(2, weight=1)
main_frame.grid_rowconfigure(3, weight=1)
main_frame.grid_rowconfigure(4, weight=1)
main_frame.grid_rowconfigure(5, weight=1)
main_frame.grid_rowconfigure(6, weight=1)
main_frame.grid_rowconfigure(7, weight=1)
main_frame.grid_rowconfigure(8, weight=1)
main_frame.grid_rowconfigure(9, weight=1)
main_frame.grid_columnconfigure(0, weight=1)
main_frame.grid_columnconfigure(1, weight=2)

# Create and place the widgets
tk.Label(main_frame, text="Key Size (bytes):").grid(row=0, column=0, padx=10, pady=10, sticky="w")
key_size_var = tk.StringVar(value='16')
key_size_menu = tk.OptionMenu(main_frame, key_size_var, '16', '24', '32', '64')
key_size_menu.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

tk.Label(main_frame, text="Key:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
key_entry = tk.Entry(main_frame, width=50)
key_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

tk.Label(main_frame, text="Message:").grid(row=2, column=0, padx=10, pady=10, sticky="w")
message_entry = tk.Text(main_frame, height=5, width=50)
message_entry.grid(row=2, column=1, padx=10, pady=10, sticky="ew")

tk.Label(main_frame, text="Encryption Mode:").grid(row=3, column=0, padx=10, pady=10, sticky="w")
mode_var = tk.StringVar(value='EAX')
mode_menu = tk.OptionMenu(main_frame, mode_var, 'EAX', 'CBC')
mode_menu.grid(row=3, column=1, padx=10, pady=10, sticky="ew")

tk.Label(main_frame, text="Encrypted Result:").grid(row=4, column=0, padx=10, pady=10, sticky="w")
encrypted_result_entry = tk.Entry(main_frame, width=50)
encrypted_result_entry.grid(row=4, column=1, padx=10, pady=10, sticky="ew")

tk.Label(main_frame, text="Decrypted Result:").grid(row=5, column=0, padx=10, pady=10, sticky="w")
decrypted_result_entry = tk.Entry(main_frame, width=50)
decrypted_result_entry.grid(row=5, column=1, padx=10, pady=10, sticky="ew")

tk.Button(main_frame, text="Encrypt", command=encrypt_message).grid(row=6, column=0, padx=10, pady=10, sticky="ew")
tk.Button(main_frame, text="Decrypt", command=decrypt_message).grid(row=6, column=1, padx=10, pady=10, sticky="ew")

# Add buttons for saving and loading files
tk.Button(main_frame, text="Save Encrypted Message", command=save_encrypted_message).grid(row=7, column=0, padx=10, pady=10, sticky="ew")
tk.Button(main_frame, text="Load Encrypted Message", command=load_encrypted_message).grid(row=7, column=1, padx=10, pady=10, sticky="ew")

# Add progress bar and status label
progress_bar = ttk.Progressbar(main_frame, mode='indeterminate', length=200)
progress_bar.grid(row=8, column=0, columnspan=2, padx=10, pady=10)
status_label = tk.Label(main_frame, text="", font=('Arial', 12, 'italic'))
status_label.grid(row=9, column=0, columnspan=2, padx=10, pady=10)

# Run the main loop
root.mainloop()
