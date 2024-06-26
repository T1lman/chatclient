# Importieren der notwendigen Module
import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter.scrolledtext import ScrolledText
import threading
import socket
from datetime import datetime
import logging
import traceback

from encryptions.RSA import generate_keypair as generate_rsa_key, encrypt as rsa_encrypt, decrypt as rsa_decrypt
from encryptions.AES import generate_random_key as generate_aes_key, aes_encrypt, aes_decrypt
from encryptions.DES import generate_random_key as generate_des_key, des_encrypt_message as triple_des_encrypt, des_decrypt_message as triple_des_decrypt

# Setup logging
logging.basicConfig(filename='chat_client.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

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

        # Button zum Verbinden mit dem Server
        self.connect_button = tk.Button(self.root, text="Connect", command=self.connect_to_server, bg="lightblue")
        self.connect_button.pack(side=tk.LEFT, padx=10, pady=10)

        # Button für Einstellungen
        self.settings_button = tk.Button(self.root, text="⚙️", command=self.open_settings, bg="lightgray")
        self.settings_button.pack(side=tk.RIGHT, padx=10, pady=10)

        self.root.mainloop()

    def open_settings(self):
        # Neues Fenster für Einstellungen öffnen
        self.settings_window = tk.Toplevel(self.root)
        self.settings_window.title("Settings")

        # Verschlüsselungsmethode Auswahl
        self.encryption_label = tk.Label(self.settings_window, text="Encryption:")
        self.encryption_label.pack(padx=10, pady=5)
        self.encryption_var = tk.StringVar(value="None")
        self.encryption_menu = tk.OptionMenu(self.settings_window, self.encryption_var, "None", "RSA", "AES", "3DES")
        self.encryption_menu.pack(padx=10, pady=5)

        # Button zum Laden eines benutzerdefinierten RSA-Schlüssels
        self.rsa_key_button = tk.Button(self.settings_window, text="Custom RSA Key", command=self.load_rsa_key)
        self.rsa_key_button.pack(padx=10, pady=5)

        # Button zum Anwenden der Einstellungen
        self.apply_button = tk.Button(self.settings_window, text="Apply", command=self.apply_settings)
        self.apply_button.pack(padx=10, pady=10)

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
                logging.error("Fehler beim Laden des RSA-Schlüssels: %s\n%s", e, traceback.format_exc())
                messagebox.showerror("Error", f"Fehler beim Laden des RSA-Schlüssels: {e}")

    def apply_settings(self):
        # Einstellungen anwenden und das Fenster schließen
        self.encryption_type = self.encryption_var.get()
        self.settings_window.destroy()

    def connect_to_server(self):
        # Verbindung zum Server herstellen
        self.host = self.host_entry.get()
        self.encryption_type = getattr(self, 'encryption_type', 'None')
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
            logging.error("Fehler beim Verbinden mit %s:%s\n%s", self.host, self.port, traceback.format_exc())
            messagebox.showerror("Connection Error", f"Fehler beim Verbinden mit {self.host}:{self.port}\n{e}")
            self.root.title("Chat Client Configuration")


    def setup_chat_interface(self):
        # Benutzeroberfläche für den Chat einrichten
        self.host_label.pack_forget()
        self.host_entry.pack_forget()
        self.port_label.pack_forget()
        self.port_entry.pack_forget()
        self.connect_button.pack_forget()
        self.settings_button.pack_forget()

        self.info_area = ScrolledText(self.root, wrap=tk.WORD, state='disabled', height=5)
        self.info_area.pack(padx=10, pady=10, fill=tk.X, expand=False)

        self.connected_users_area = ScrolledText(self.root, wrap=tk.WORD, state='disabled', height=10)
        self.connected_users_area.pack(padx=10, pady=10, fill=tk.X, expand=False)

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
        try:
            self.client_socket.send(f"{self.public_key[0]},{self.public_key[1]}".encode())
            server_public_key_str = self.client_socket.recv(4096).decode()
            self.server_public_key = tuple(map(int, server_public_key_str.split(',')))
        except Exception as e:
            logging.error("Fehler beim Austausch der öffentlichen Schlüssel: %s\n%s", e, traceback.format_exc())

    def send_encryption_type(self):
        # Verschlüsselungstyp an den Server senden
        try:
            encrypted_encryption_type = rsa_encrypt(self.encryption_type.encode(), self.server_public_key)
            self.client_socket.send(encrypted_encryption_type)
        except Exception as e:
            logging.error("Fehler beim Senden des Verschlüsselungstyps: %s\n%s", e, traceback.format_exc())

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
                logging.error("Fehler beim Senden der Nachricht: %s\n%s", e, traceback.format_exc())

    def receive_messages(self):
        while True:
            # Nachrichten vom Server empfangen
            try:
                encrypted_message = self.client_socket.recv(4096)
                if not encrypted_message:
                    break

                if self.encryption_type == "RSA":
                    message = rsa_decrypt(encrypted_message, self.private_key)
                elif self.encryption_type == "AES":
                    message = aes_decrypt(encrypted_message, self.aes_key)
                elif self.encryption_type == "3DES":
                    message = triple_des_decrypt(encrypted_message.decode(), self.triple_des_key)
                else:
                    message = encrypted_message.decode()
                
                if message.startswith("Connected Users:"):
                    self.update_connected_users(message)
                else:
                    self.display_message(message)
            except Exception as e:
                logging.error("Fehler beim Empfangen der Nachricht: %s\n%s", e, traceback.format_exc())
                break

        

    def display_message(self, message):
        # Nachricht im Chat-Fenster anzeigen
        currentDateAndTime = datetime.now()
        currentTime = currentDateAndTime.strftime("%H:%M:%S")
        self.chat_area.configure(state='normal')
        self.chat_area.insert(tk.END, f"[{currentTime}] {message}\n")
        self.chat_area.configure(state='disabled')
        self.chat_area.see(tk.END)

    def start_receiving_thread(self):
        # Thread zum Empfangen von Nachrichten starten
        self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        self.receive_thread.start()

    def restart_client(self):
        self.root.destroy()
        self.client_socket.close()
        message = "quit"
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
            logging.error("Fehler beim Neustarten des Server: %s\n%s", e, traceback.format_exc())
        self.__init__()
    def update_connected_users(self, connected_users):
        self.connected_users_area.configure(state='normal')
        self.connected_users_area.delete(1.0, tk.END)
        self.connected_users_area.insert(tk.END, connected_users)
        self.connected_users_area.configure(state='disabled')

if __name__ == "__main__":
    client = ChatClient()
