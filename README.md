# ChatClient
 ChatClient mit verschiedenen Verschlüsslungen (none, RSA, AES, DES3)




## Dokumentation: Herausforderungen und Lösungen bei der Entwicklung des Chat-Clients und -Servers

### Probleme und Lösungen beim Chat-Client

1. **Problem: Unsichere RSA-Schlüsseldatei**
   - **Beschreibung:** Beim Laden eines benutzerdefinierten RSA-Schlüssels aus einer Datei konnte der Client aufgrund falscher Formatierung oder unzureichender Überprüfung der Schlüsseldatei abstürzen.
   - **Lösung:** Eine Validierung des Schlüsseldateiinhalts wurde implementiert, um sicherzustellen, dass die Datei das richtige Format hat. Zudem wurden Fehlermeldungen hinzugefügt, um den Benutzer über mögliche Probleme zu informieren.

   ```python
   def load_rsa_key(self):
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
   ```

2. **Problem: Verbindungsprobleme zum Server**
   - **Beschreibungg:** Der Client konnte manchmal keine Verbindung zum Server herstellen, insbesondere wenn die Host- oder Port-Eingaben fehlerhaft waren.
   - **Lösung:** Eine umfassende Validierung der Eingaben und detaillierte Fehlermeldungen wurden hinzugefügt, um sicherzustellen, dass Host und Port korrekt eingegeben wurden.

   ```python
   def connect_to_server(self):
       self.host = self.host_entry.get()
       self.encryption_type = self.encryption_var.get()
       try:
           self.port = int(self.port_entry.get())
           if not self.host or not self.port:
               raise ValueError("Host und Port müssen angegeben werden")
           self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
           self.client_socket.connect((self.host, self.port))
           self.root.title(f"{self.host}:{self.port} - Chat Client")
           # Weitere Initialisierungsschritte...
       except (ValueError, socket.error) as e:
           messagebox.showerror("Connection Error", f"Fehler beim Verbinden mit {self.host}:{self.port}\n{e}")
           self.root.title("Chat Client Configuration")
   ```

3. **Problem: Synchronisationsprobleme beim Nachrichtenaustausch**
   - **Beschreibung:** Es traten Verzögerungen und Synchronisationsprobleme beim Empfang und senden von Nachrichten auf.
   - **Lösung:** Ein dedizierter Empfangsthread wurde eingeführt, um eingehende Nachrichten unabhängig vom Hauptthread zu verarbeiten. Dies stellte sicher, dass der Benutzer weiterhin Nachrichten senden konnte, während eingehende Nachrichten verarbeitet wurden.

   ```python
   def start_receiving_thread(self):
       self.receive_thread = threading.Thread(target=self.receive_messages)
       self.receive_thread.start()
   ```

4. **Problem: Fehlerhafte Nachrichtenverschlüsselung**
   - **Beschreibung:** Die Verschlüsselung von Nachrichten konnte aufgrund falscher Schlüsselaustauschmechanismen fehlschlagen, was zu unlesbaren Nachrichten führte.
   - **Lösung:** Der Austausch der öffentlichen Schlüssel zwischen Client und Server wurde verfeinert, um sicherzustellen, dass die richtigen Schlüssel verwendet werden. Zudem wurden detaillierte Fehlerbehandlungsroutinen implementiert.

   ```python
   def exchange_public_keys(self):
       self.client_socket.send(f"{self.public_key[0]},{self.public_key[1]}".encode())
       server_public_key_str = self.client_socket.recv(4096).decode()
       self.server_public_key = tuple(map(int, server_public_key_str.split(',')))
   ```

### Probleme und Lösungen beim Chat-Server

1. **Problem: Fehlerhafte Verarbeitung von Client-Verbindungen**
   - **Beschreibung:** Der Server stürzte ab, wenn er versuchte, mehr als eine Verbindung gleichzeitig zu verarbeiten.
   - **Lösung:** Ein Threading Modell wurde implementiert, um jede Client-Verbindung in einem separaten Thread zu behandeln, was zu einer stabileren und skalierbareren Lösung führte.

   ```python
   def start_accepting_thread(self):
       self.server_thread = threading.Thread(target=self.accept_clients)
       self.server_thread.start()
   ```

2. **Problem: Unzureichende Verschlüsselung und Entschlüsselung**
   - **Beschreibung:** Nachrichten wurden manchmal falsch entschlüsselt, was zu unverständlichen Texten führte.
   - **Lösung:** Der Mechanismus zur Auswahl der Verschlüsselungsmethode wurde verfeinert, und die entsprechenden Schlüssel wurden korrekt ausgetauscht und verwendet.

   ```python
   def handle_client(self, conn, addr):
       try:
           # Öffentliche Schlüssel austauschen
           conn.send(f"{self.public_key[0]},{self.public_key[1]}".encode())
           client_public_key_str = conn.recv(4096).decode()
           client_public_key = tuple(map(int, client_public_key_str.split(',')))
           self.client_public_keys[conn] = client_public_key
           # Weitere Verarbeitung...
       except Exception as e:
           print(f"Fehler bei der Handhabung des Clients {addr}: {e}")
   ```

3. **Problem: Schwierigkeiten bei der Aktualisierung der Benutzeroberfläche**
   - **Beschreibung:** Die Benutzeroberfläche des Servers aktualisierte sich nicht korrekt, insbesondere bei der Anzeige der verbundenen Clients.
   - **Lösung:** Die Methode zur Aktualisierung der Benutzeroberfläche wurde optimiert, um sicherzustellen, dass alle Änderungen sofort angezeigt werden.

   ```python
   def update_clients_area(self):
       self.clients_area.configure(state='normal')
       self.clients_area.delete(1.0, tk.END)
       for client in self.clients:
           encryption_type = self.encryption_methods.get(client, "Unknown")
           client_info = f"Client {client.getpeername()} - Encryption: {encryption_type}"
           if encryption_type == "RSA":
               client_info += f" - Client Public Key: {self.client_public_keys.get(client)}"
           self.clients_area.insert(tk.END, client_info + "\n")
       self.clients_area.configure(state='disabled')
   ```

4. **Problem: Unzureichende Fehlerbehandlung**
   - **Beschreibung:** Der Server stürzte bei unvorhergesehenen Fehlern ab, was zu einem kompletten Systemausfall führte.
   - **Lösung:** Umfassende Fehlerbehandlungsroutinen wurden hinzugefügt, um sicherzustellen, dass der Server stabil bleibt und Verbindungsprobleme korrekt behandelt werden.

   ```python
   def broadcast_message(self, message):
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
   ```

Durch die Identifizierung und Lösung dieser Probleme konnte sowohl der Client als auch der Server stabiler und zuverlässiger gemacht werden. Die Implementierung einer robusten Fehlerbehandlung und die Optimierung der Schlüsselverwaltung haben dazu beigetragen, die Sicherheit und Effizienz des gesamten Systems zu verbessern.