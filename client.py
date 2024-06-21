# Importieren der notwendigen Module
import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
import threading
import socket
from datetime import datetime

from encryptions.RSA import generate_keypair as generate_rsa_key, encrypt as rsa_encrypt, decrypt as rsa_decrypt
from encryptions.AES import generate_random_key as generate_aes_key, aes_encrypt, aes_decrypt
from encryptions.DES import generate_random_key as generate_des_key, des_encrypt_message as triple_des_encrypt, des_decrypt_message as triple_des_decrypt

class ChatClient:
    def __init__(self):
        # Initialisierung der Benutzeroberfläche
        self.root = tk.Tk()
        self.root.title("Chat Client Configuration")

        # Host-Adresse Eingabefeld
        self.host_label = tk.Label(self.root, text="Host Address:")
        self.host_label.pack(padx=10, pady=5)
        self.host_entry = tk.Entry(self.root)
        self.host_entry.pack(padx=10, pady=5)

        # Port Eingabefeld
        self.port_label = tk.Label(self.root, text="Port:")
        self.port_label.pack(padx=10, pady=5)
        self.port_entry = tk.Entry(self.root)
        self.port_entry.pack(padx=10, pady=5)

        # Verschlüsselungsmethode Auswahl
        self.encryption_label = tk.Label(self.root, text="Encryption:")
        self.encryption_label.pack(padx=10, pady=5)
        self.encryption_var = tk.StringVar(value="None")
        self.encryption_menu = tk.OptionMenu(self.root, self.encryption_var, "None", "RSA", "AES", "3DES")
        self.encryption_menu.pack(padx=10, pady=5)

        # Button zum Laden eines benutzerdefinierten RSA-Schlüssels
        self.rsa_key_button = tk.Button(self.root, text="Custom RSA Key", command=self.load_rsa_key)
        self.rsa_key_button.pack(padx=10, pady=5)

        # Button zum Verbinden mit dem Server
        self.connect_button = tk.Button(self.root, text="Connect", command=self.connect_to_server, bg="lightblue")
        self.connect_button.pack(padx=10, pady=10)

        self.root.mainloop()

    def load_rsa_key(self):
        # Laden eines benutzerdefinierten RSA-Schlüssels aus einer Datei
        key_file = filedialog.askopenfilename(title="Select RSA Key File")
        if key_file:
            try:
                with open(key_file, 'r') as f:
                    key_data = f.read().strip()
                    public_key_str, private_key_str = key_data.split("\n")
                    self.public_key = tuple(map(int, public_key_str.strip("()").split(",")))
                    self.private_key = tuple(map(int, private_key_str.strip("()").split(",")))
                    messagebox.showinfo("RSA Key Loaded", "Benutzerdefinierter RSA-Schlüssel wurde erfolgreich geladen.")
            except Exception as e:
                messagebox.showerror("Error", f"Fehler beim Laden des RSA-Schlüssels: {e}")

    def connect_to_server(self):
        # Verbindung zum Server herstellen
        self.host = self.host_entry.get()
        self.encryption_type = self.encryption_var.get()
        try:
            self.port = int(self.port_entry.get())
            if not self.host or not self.port:
                raise ValueError("Host und Port müssen angegeben werden")

            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.host, self.port))
            self.root.title(f"{self.host}:{self.port} - Chat Client")

            self.setup_chat_interface()
            self.exchange_public_keys()
            self.send_encryption_type()
            if self.encryption_type == "AES":
                self.aes_key = generate_aes_key()
                encrypted_aes_key = rsa_encrypt(self.aes_key.encode(), self.server_public_key)
                self.client_socket.send(encrypted_aes_key)
            elif self.encryption_type == "3DES":
                self.triple_des_key = generate_des_key()
                encrypted_3des_key = rsa_encrypt(bytes(self.triple_des_key), self.server_public_key)
                self.client_socket.send(encrypted_3des_key)
            self.start_receiving_thread()
            self.display_encryption_info()
        except (ValueError, socket.error) as e:
            messagebox.showerror("Connection Error", f"Fehler beim Verbinden mit {self.host}:{self.port}\n{e}")
            self.root.title("Chat Client Configuration")

    def setup_chat_interface(self):
        # Benutzeroberfläche für den Chat einrichten
        self.host_label.pack_forget()
        self.host_entry.pack_forget()
        self.port_label.pack_forget()
        self.port_entry.pack_forget()
        self.encryption_label.pack_forget()
        self.encryption_menu.pack_forget()
        self.rsa_key_button.pack_forget()
        self.connect_button.pack_forget()

        self.info_area = ScrolledText(self.root, wrap=tk.WORD, state='disabled', height=5)
        self.info_area.pack(padx=10, pady=10, fill=tk.X, expand=False)

        self.chat_area = ScrolledText(self.root, wrap=tk.WORD, state='disabled')
        self.chat_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.entry_field = tk.Entry(self.root)
        self.entry_field.pack(padx=10, pady=10, fill=tk.X, expand=False)
        self.entry_field.bind("<Return>", self.send_message)

        self.restart_button = tk.Button(self.root, text="Restart", command=self.restart_client)
        self.restart_button.pack(padx=10, pady=5)

        if not hasattr(self, 'public_key') or not hasattr(self, 'private_key'):
            self.public_key, self.private_key = generate_rsa_key(16)

    def exchange_public_keys(self):
        # Öffentliche Schlüssel austauschen
        self.client_socket.send(f"{self.public_key[0]},{self.public_key[1]}".encode())
        server_public_key_str = self.client_socket.recv(4096).decode()
        self.server_public_key = tuple(map(int, server_public_key_str.split(',')))

    def send_encryption_type(self):
        # Verschlüsselungstyp an den Server senden
        encrypted_encryption_type = rsa_encrypt(self.encryption_type.encode(), self.server_public_key)
        self.client_socket.send(encrypted_encryption_type)

    def display_encryption_info(self):
        # Anzeigen der Verschlüsselungsinformationen
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
        # Nachricht an den Server senden
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
                    encrypted_message = message.encode()
                self.client_socket.send(encrypted_message)
                self.entry_field.delete(0, tk.END)
                if message.lower() == "quit":
                    self.client_socket.close()
                    self.root.quit()
            except Exception as e:
                print(f"Fehler beim Senden der Nachricht: {e}")

    def receive_messages(self):
        while True:
            # Nachrichten vom Server empfangen
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
                            decrypted_message = encrypted_message.decode()
                        self.display_message(decrypted_message)
                    except Exception as e:
                        print(f"Fehler beim Entschlüsseln der Nachricht: {e}")
                else:
                    break
            except Exception as e:
                print(f"Fehler beim Empfangen der Nachricht: {e}")
                break

    def display_message(self, message):
        # Nachricht im Chat-Fenster anzeigen
        currentDateAndTime = datetime.now()
        currentTime = currentDateAndTime.strftime("%H:%M:%S")

        self.chat_area.configure(state='normal')
        self.chat_area.insert(tk.END, currentTime + " " + message + "\n")
        self.chat_area.configure(state='disabled')
        self.chat_area.see(tk.END)

    def start_receiving_thread(self):
        # Thread zum Empfangen von Nachrichten starten
        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.start()

    def restart_client(self):
        # Client neu starten und zur Konfigurationsansicht zurückkehren
        self.client_socket.close()
        self.root.destroy()
        self.__init__()

if __name__ == "__main__":
    client = ChatClient()
