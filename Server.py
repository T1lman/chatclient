# Importieren der notwendigen Module
import tkinter as tk
from tkinter import messagebox
from tkinter.scrolledtext import ScrolledText
import threading
import socket
from datetime import datetime

from encryptions.RSA import generate_keypair as generate_rsa_key, encrypt as rsa_encrypt, decrypt as rsa_decrypt
from encryptions.AES import generate_random_key as generate_aes_key, aes_encrypt, aes_decrypt
from encryptions.DES import generate_random_key as generate_des_key, des_encrypt_message as triple_des_encrypt, des_decrypt_message as triple_des_decrypt

class ChatServer:
    def __init__(self):
        # Initialisierung der Benutzeroberfläche
        self.root = tk.Tk()
        self.root.title("Chat Server Configuration")

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

        # Start-Button
        self.start_button = tk.Button(self.root, text="Start Server", command=self.setup_server)
        self.start_button.pack(padx=10, pady=10)

        self.root.mainloop()

    def setup_server(self):
        # Einrichten des Servers
        self.host = self.host_entry.get()
        try:
            self.port = int(self.port_entry.get())
            if not self.host or not self.port:
                raise ValueError("Host und Port müssen angegeben werden")

            # Socket einrichten
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.root.title(f"{self.host}:{self.port} - Chat Server")

            self.setup_chat_interface()
            self.start_accepting_thread()
        except (ValueError, socket.error) as e:
            messagebox.showerror("Server Error", f"Fehler beim Hosting des Servers auf {self.host}:{self.port}\n{e}")
            self.root.title("Chat Server Configuration")

    def setup_chat_interface(self):
        # Benutzeroberfläche für den Chat einrichten
        self.host_label.pack_forget()
        self.host_entry.pack_forget()
        self.port_label.pack_forget()
        self.port_entry.pack_forget()
        self.start_button.pack_forget()

        self.clients_area = ScrolledText(self.root, wrap=tk.WORD, state='disabled', height=10)
        self.clients_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.messages_area = ScrolledText(self.root, wrap=tk.WORD, state='disabled')
        self.messages_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.clients = []
        self.client_public_keys = {}
        self.client_aes_keys = {}
        self.client_3des_keys = {}
        self.encryption_methods = {}
        self.public_key, self.private_key = generate_rsa_key(16)

    def start_accepting_thread(self):
        # Thread zum Akzeptieren von Clients starten
        self.server_thread = threading.Thread(target=self.accept_clients)
        self.server_thread.start()

    def accept_clients(self):
        while True:
            # Akzeptieren neuer Verbindungen
            conn, addr = self.server_socket.accept()
            self.clients.append(conn)
            threading.Thread(target=self.handle_client, args=(conn, addr)).start()

    def handle_client(self, conn, addr):
        try:
            # Öffentliche Schlüssel austauschen
            conn.send(f"{self.public_key[0]},{self.public_key[1]}".encode())
            client_public_key_str = conn.recv(4096).decode()
            client_public_key = tuple(map(int, client_public_key_str.split(',')))
            self.client_public_keys[conn] = client_public_key

            # Verschlüsselungsmethode empfangen
            encryption_type_encrypted = conn.recv(4096)
            encryption_type = rsa_decrypt(encryption_type_encrypted, self.private_key)
            self.encryption_methods[conn] = encryption_type

            # AES- oder 3DES-Schlüssel empfangen, falls ausgewählt
            if encryption_type == "AES":
                aes_key_encrypted = conn.recv(4096)
                aes_key = rsa_decrypt(aes_key_encrypted, self.private_key)
                self.client_aes_keys[conn] = aes_key
            elif encryption_type == "3DES":
                triple_des_key_encrypted = conn.recv(4096)
                triple_des_key = list(rsa_decrypt(triple_des_key_encrypted, self.private_key).encode())
                self.client_3des_keys[conn] = list(triple_des_key)

            self.update_clients_area()

            while True:
                # Nachrichten von Clients empfangen und verarbeiten
                message = conn.recv(4096)
                if message:
                    try:
                        if encryption_type == "RSA":
                            decrypted_message = rsa_decrypt(message, self.private_key)
                        elif encryption_type == "AES":
                            decrypted_message = aes_decrypt(message, self.client_aes_keys[conn])
                        elif encryption_type == "3DES":
                            decrypted_message = triple_des_decrypt(message.decode(), self.client_3des_keys[conn])
                        else:
                            decrypted_message = message.decode()
                        self.broadcast_message(f"{addr}: {decrypted_message}")
                    except Exception as e:
                        print(f"Fehler beim Entschlüsseln der Nachricht von {addr}: {e}")
                else:
                    break
        except Exception as e:
            print(f"Fehler bei der Handhabung des Clients {addr}: {e}")
        finally:
            # Verbindung schließen und Client entfernen
            conn.close()
            self.clients.remove(conn)
            self.update_clients_area()

    def broadcast_message(self, message):
        # Nachricht an alle Clients senden
        currentDateAndTime = datetime.now()
        currentTime = currentDateAndTime.strftime("%H:%M:%S")

        self.messages_area.configure(state='normal')
        self.messages_area.insert(tk.END, currentTime + " " + message + "\n")
        self.messages_area.configure(state='disabled')
        self.messages_area.see(tk.END)

        for client in self.clients:
            try:
                if self.encryption_methods[client] == "RSA":
                    encrypted_message = rsa_encrypt(message.encode(), self.client_public_keys[client])
                elif self.encryption_methods[client] == "AES":
                    encrypted_message = aes_encrypt(message, self.client_aes_keys[client])
                elif self.encryption_methods[client] == "3DES":
                    encrypted_message = triple_des_encrypt(message, self.client_3des_keys[client]).encode()
                else:
                    encrypted_message = message.encode()
                client.send(encrypted_message)
            except Exception as e:
                print(f"Fehler beim Senden der Nachricht an den Client {client.getpeername()}: {e}")

    def update_clients_area(self):
        # Aktualisierung der Clients-Anzeige
        self.clients_area.configure(state='normal')
        self.clients_area.delete(1.0, tk.END)
        for client in self.clients:
            encryption_type = self.encryption_methods.get(client, "Unknown")
            client_info = f"Client {client.getpeername()} - Encryption: {encryption_type}"
            if encryption_type == "RSA":
                client_info += f" - Client Public Key: {self.client_public_keys.get(client)}"
            self.clients_area.insert(tk.END, client_info + "\n")
        self.clients_area.configure(state='disabled')

if __name__ == "__main__":
    server = ChatServer()
