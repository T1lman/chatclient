import tkinter as tk
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText
import threading
import socket
from datetime import datetime



from RSA import generate_keypair as generate_rsa_key, encrypt as rsa_encrypt, decrypt as rsa_decrypt
from AES import generate_random_key as generate_aes_key, aes_encrypt, aes_decrypt
from DES import generate_random_key as generate_des_key, des_encrypt_message as triple_des_encrypt, des_decrypt_message as triple_des_decrypt

class ChatClient:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Chat Client Configuration")

        self.host_label = tk.Label(self.root, text="Host Address:")
        self.host_label.pack(padx=10, pady=5)
        self.host_entry = tk.Entry(self.root)
        self.host_entry.pack(padx=10, pady=5)

        self.port_label = tk.Label(self.root, text="Port:")
        self.port_label.pack(padx=10, pady=5)
        self.port_entry = tk.Entry(self.root)
        self.port_entry.pack(padx=10, pady=5)

        self.encryption_label = tk.Label(self.root, text="Encryption:")
        self.encryption_label.pack(padx=10, pady=5)
        self.encryption_var = tk.StringVar(value="None")
        self.encryption_menu = tk.OptionMenu(self.root, self.encryption_var, "None", "RSA", "AES", "3DES")
        self.encryption_menu.pack(padx=10, pady=5)

        self.connect_button = tk.Button(self.root, text="Connect", command=self.connect_to_server, bg="lightblue")
        self.connect_button.pack(padx=10, pady=10)

        self.root.mainloop()

    def connect_to_server(self):
        self.host = self.host_entry.get()
        self.encryption_type = self.encryption_var.get()
        try:
            self.port = int(self.port_entry.get())
            if not self.host or not self.port:
                raise ValueError("Host and port must be specified")

            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.host, self.port))
            self.root.title(f"{self.host}:{self.port} - Chat Client")

            self.setup_chat_interface()
            self.send_encryption_type()
            if self.encryption_type == "RSA":
                self.send_public_key()
                self.receive_server_public_key()
            elif self.encryption_type == "AES":
                self.aes_key = generate_aes_key()
                self.client_socket.send(self.aes_key.encode())
            elif self.encryption_type == "3DES":
                self.triple_des_key = generate_des_key()
                self.client_socket.send(bytes(self.triple_des_key))
            self.start_receiving_thread()
            self.display_encryption_info()
        except (ValueError, socket.error) as e:
            messagebox.showerror("Connection Error", f"Failed to connect to {self.host}:{self.port}\n{e}")
            self.root.title("Chat Client Configuration")

    def setup_chat_interface(self):
        self.host_label.pack_forget()
        self.host_entry.pack_forget()
        self.port_label.pack_forget()
        self.port_entry.pack_forget()
        self.encryption_label.pack_forget()
        self.encryption_menu.pack_forget()
        self.connect_button.pack_forget()

        self.info_area = ScrolledText(self.root, wrap=tk.WORD, state='disabled', height=5)
        self.info_area.pack(padx=10, pady=10, fill=tk.X, expand=False)

        self.chat_area = ScrolledText(self.root, wrap=tk.WORD, state='disabled')
        self.chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.entry_field = tk.Entry(self.root)
        self.entry_field.pack(padx=10, pady=10, fill=tk.X, expand=False)
        self.entry_field.bind("<Return>", self.send_message)

        self.public_key, self.private_key = generate_rsa_key(16)

    def send_encryption_type(self):
        self.client_socket.send(self.encryption_type.encode())

    def send_public_key(self):
        self.client_socket.send(f"{self.public_key[0]},{self.public_key[1]}".encode())

    def receive_server_public_key(self):
        server_public_key_str = self.client_socket.recv(4096).decode()
        self.server_public_key = tuple(map(int, server_public_key_str.split(',')))

    def display_encryption_info(self):
        self.info_area.configure(state='normal')
        self.info_area.delete(1.0, tk.END)
        self.info_area.insert(tk.END, f"My Address: {self.client_socket.getsockname()}\n")
        self.info_area.insert(tk.END, f"Server Address: {self.host}:{self.port}\n")
        self.info_area.insert(tk.END, f"Encryption Type: {self.encryption_type}\n")
        if self.encryption_type == "RSA":
            self.info_area.insert(tk.END, f"Public Key: {self.public_key}\n")
            self.info_area.insert(tk.END, f"Server Public Key: {self.server_public_key}\n")
        elif self.encryption_type == "AES":
            self.info_area.insert(tk.END, f"AES Key: {self.aes_key}\n")
        elif self.encryption_type == "3DES":
            self.info_area.insert(tk.END, f"3DES Key: {bytes(self.triple_des_key).hex()}\n")
        self.info_area.configure(state='disabled')

    def send_message(self, event=None):
        message = self.entry_field.get()
        if message:
            try:
                if self.encryption_type == "RSA":
                    encrypted_message = rsa_encrypt(message.encode(), self.server_public_key)
                elif self.encryption_type == "AES":
                    encrypted_message = aes_encrypt(message, self.aes_key)
                elif self.encryption_type == "3DES":
                    encrypted_message = triple_des_encrypt(message, self.triple_des_key).encode()
                else:
                    encrypted_message = message.encode()  # Plaintext
                self.client_socket.send(encrypted_message)
                self.entry_field.delete(0, tk.END)
                if message.lower() == "quit":
                    self.client_socket.close()
                    self.root.quit()
            except Exception as e:
                print(f"Error sending message: {e}")

    def receive_messages(self):
        while True:
            try:
                encrypted_message = self.client_socket.recv(4096)
                if encrypted_message:
                    try:
                        if self.encryption_type == "RSA":
                            decrypted_message = rsa_decrypt(encrypted_message, self.private_key)
                        elif self.encryption_type == "AES":
                            decrypted_message = aes_decrypt(encrypted_message, self.aes_key)
                        elif self.encryption_type == "3DES":
                            decrypted_message = triple_des_decrypt(encrypted_message.decode(), self.triple_des_key)
                        else:
                            decrypted_message = encrypted_message.decode()  # Plaintext
                        self.display_message(decrypted_message)
                    except Exception as e:
                        print(f"Error decrypting message: {e}")
                else:
                    break
            except Exception as e:
                print(f"Error receiving message: {e}")
                break

    def display_message(self, message):
        currentDateAndTime = datetime.now()
        currentTime = currentDateAndTime.strftime("%H:%M:%S")

        self.chat_area.configure(state='normal')
        self.chat_area.insert(tk.END, currentTime + " " + message + "\n")
        self.chat_area.configure(state='disabled')
        self.chat_area.see(tk.END)

    def start_receiving_thread(self):
        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.start()

if __name__ == "__main__":
    client = ChatClient()