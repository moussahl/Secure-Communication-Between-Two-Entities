import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import socket
import pickle
from rsa import RSA
from feistel import encrypt_message, decrypt_message
from hash_function import CustomHash


class SecureServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure Server - Encrypted Communication")
        self.root.geometry("700x700")
        self.root.resizable(True, True)
        
        # Colors
        self.bg_color = "#1e1e2e"
        self.fg_color = "#cdd6f4"
        self.accent_color = "#f5c2e7"
        self.success_color = "#a6e3a1"
        self.error_color = "#f38ba8"
        self.panel_color = "#313244"
        
        self.root.configure(bg=self.bg_color)
        
        # Server variables
        self.server_socket = None
        self.client_conn = None
        self.running = False
        self.rsa = RSA(key_size=512)
        self.public_key = None
        self.private_key = None
        self.symmetric_key = None
        self.hasher = CustomHash()
        
        self.create_widgets()
        
    def create_widgets(self):
        """Create GUI elements"""
        
        # Title
        title_frame = tk.Frame(self.root, bg=self.bg_color)
        title_frame.pack(fill=tk.X, padx=20, pady=10)
        
        title_label = tk.Label(
            title_frame,
            text="🔐 Secure Server",
            font=("Arial", 24, "bold"),
            bg=self.bg_color,
            fg=self.accent_color
        )
        title_label.pack()
        
        subtitle_label = tk.Label(
            title_frame,
            text="Encrypted Server - Can Send & Receive Messages",
            font=("Arial", 10),
            bg=self.bg_color,
            fg=self.fg_color
        )
        subtitle_label.pack()
        
        # Server Control Panel
        control_frame = tk.LabelFrame(
            self.root,
            text="Server Control",
            font=("Arial", 11, "bold"),
            bg=self.panel_color,
            fg=self.fg_color,
            relief=tk.RIDGE,
            bd=2
        )
        control_frame.pack(fill=tk.X, padx=20, pady=5)
        
        control_inner = tk.Frame(control_frame, bg=self.panel_color)
        control_inner.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(
            control_inner,
            text="Port:",
            font=("Arial", 10),
            bg=self.panel_color,
            fg=self.fg_color
        ).pack(side=tk.LEFT, padx=5)
        
        self.port_entry = tk.Entry(
            control_inner,
            font=("Arial", 10),
            width=8,
            bg="#45475a",
            fg=self.fg_color
        )
        self.port_entry.insert(0, "9999")
        self.port_entry.pack(side=tk.LEFT, padx=5)
        
        self.start_btn = tk.Button(
            control_inner,
            text="🚀 Start Server",
            font=("Arial", 10, "bold"),
            bg=self.success_color,
            fg="#1e1e2e",
            command=self.start_server,
            cursor="hand2",
            width=15
        )
        self.start_btn.pack(side=tk.LEFT, padx=10)
        
        self.status_label = tk.Label(
            control_inner,
            text="● Stopped",
            font=("Arial", 10, "bold"),
            bg=self.panel_color,
            fg=self.error_color
        )
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        # Encryption Status
        enc_frame = tk.LabelFrame(
            self.root,
            text="Encryption Status",
            font=("Arial", 11, "bold"),
            bg=self.panel_color,
            fg=self.fg_color,
            relief=tk.RIDGE,
            bd=2
        )
        enc_frame.pack(fill=tk.X, padx=20, pady=5)
        
        enc_inner = tk.Frame(enc_frame, bg=self.panel_color)
        enc_inner.pack(fill=tk.X, padx=10, pady=10)
        
        self.rsa_indicator = self.create_indicator(enc_inner, "RSA", "⏳ Waiting...")
        self.client_indicator = self.create_indicator(enc_inner, "Client", "⏳ No connection")
        
        # Chat Display
        chat_frame = tk.LabelFrame(
            self.root,
            text="Secure Chat",
            font=("Arial", 11, "bold"),
            bg=self.panel_color,
            fg=self.fg_color,
            relief=tk.RIDGE,
            bd=2
        )
        chat_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=5)
        
        self.chat_display = scrolledtext.ScrolledText(
            chat_frame,
            font=("Courier New", 10),
            bg="#181825",
            fg=self.fg_color,
            wrap=tk.WORD,
            state=tk.DISABLED,
            height=20
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Text tags
        self.chat_display.tag_config("system", foreground="#a6adc8")
        self.chat_display.tag_config("sent", foreground="#f5c2e7")
        self.chat_display.tag_config("received", foreground="#89b4fa")
        self.chat_display.tag_config("error", foreground="#f38ba8")
        
        # Message Input
        input_frame = tk.Frame(self.root, bg=self.bg_color)
        input_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(
            input_frame,
            text="Reply to Client:",
            font=("Arial", 10, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        ).pack(anchor=tk.W)
        
        msg_frame = tk.Frame(input_frame, bg=self.bg_color)
        msg_frame.pack(fill=tk.X, pady=5)
        
        self.message_entry = tk.Entry(
            msg_frame,
            font=("Arial", 11),
            bg="#45475a",
            fg=self.fg_color,
            state=tk.DISABLED
        )
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=8)
        self.message_entry.bind("<Return>", lambda e: self.send_message())
        
        self.send_btn = tk.Button(
            msg_frame,
            text="📤 Send Reply",
            font=("Arial", 11, "bold"),
            bg=self.accent_color,
            fg="#1e1e2e",
            command=self.send_message,
            cursor="hand2",
            width=15,
            state=tk.DISABLED
        )
        self.send_btn.pack(side=tk.LEFT, padx=10)
        
        # Footer
        footer = tk.Label(
            self.root,
            text="🔐 Server: Receives & sends encrypted messages using RSA + Feistel + SHA-256",
            font=("Arial", 8),
            bg=self.bg_color,
            fg="#6c7086"
        )
        footer.pack(pady=5)
        
    def create_indicator(self, parent, label, status):
        frame = tk.Frame(parent, bg=self.panel_color)
        frame.pack(side=tk.LEFT, padx=20)
        
        tk.Label(
            frame,
            text=label + ":",
            font=("Arial", 9, "bold"),
            bg=self.panel_color,
            fg=self.fg_color
        ).pack(side=tk.LEFT, padx=5)
        
        indicator = tk.Label(
            frame,
            text=status,
            font=("Arial", 9),
            bg=self.panel_color,
            fg="#6c7086"
        )
        indicator.pack(side=tk.LEFT)
        
        return indicator
        
    def log_message(self, message, tag="system"):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, f"{message}\n", tag)
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED)
        
    def start_server(self):
        if self.running:
            self.stop_server()
        else:
            port = int(self.port_entry.get())
            thread = threading.Thread(target=self._server_thread, args=(port,))
            thread.daemon = True
            thread.start()
            
    def _server_thread(self, port):
        try:
            # Generate RSA keys
            self.root.after(0, lambda: self.log_message("🔐 Generating RSA keys...", "system"))
            self.public_key, self.private_key = self.rsa.generate_keys()
            self.root.after(0, lambda: self.log_message("✓ RSA keys generated", "system"))
            self.root.after(0, lambda: self.rsa_indicator.config(text="✓ Ready", fg=self.success_color))
            
            # Create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('127.0.0.1', port))
            self.server_socket.listen(1)
            
            self.running = True
            self.root.after(0, self._update_running_ui)
            
            self.root.after(0, lambda: self.log_message(f"🚀 Server started on port {port}", "system"))
            self.root.after(0, lambda: self.log_message("⏳ Waiting for client...\n", "system"))
            
            # Accept connection
            self.client_conn, addr = self.server_socket.accept()
            self.root.after(0, lambda: self.log_message(f"✓ Client connected: {addr[0]}:{addr[1]}\n", "system"))
            self.root.after(0, lambda: self.client_indicator.config(text=f"✓ Connected", fg=self.success_color))
            
            # Send public key
            self.root.after(0, lambda: self.log_message("📤 Sending public key to client...", "system"))
            self.client_conn.send(pickle.dumps(self.public_key))
            
            # Receive symmetric key
            self.root.after(0, lambda: self.log_message("📥 Receiving encrypted symmetric key...", "system"))
            encrypted_key = pickle.loads(self.client_conn.recv(4096))
            self.symmetric_key = self.rsa.decrypt(encrypted_key, self.private_key)
            
            self.root.after(0, lambda: self.log_message(f"✓ Symmetric key: '{self.symmetric_key}'", "system"))
            self.root.after(0, lambda: self.log_message("="*60 + "\n✅ SECURE CHANNEL ESTABLISHED\n" + "="*60 + "\n", "system"))
            
            # Enable sending
            self.root.after(0, lambda: self.message_entry.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.send_btn.config(state=tk.NORMAL))
            
            # Start receiving messages
            self.receive_messages()
            
        except Exception as e:
            self.root.after(0, lambda: self.log_message(f"❌ Error: {str(e)}", "error"))
            self.root.after(0, self.stop_server)
            
    def receive_messages(self):
        while self.running and self.client_conn:
            try:
                data = self.client_conn.recv(8192)
                if not data or data == b'EXIT':
                    self.root.after(0, lambda: self.log_message("\n⚠ Client disconnected", "system"))
                    break
                
                package = pickle.loads(data)
                encrypted_msg = package['encrypted_msg']
                msg_hash = package['hash']
                
                # Verify hash
                calculated_hash = self.hasher.hash_bytes(encrypted_msg)
                
                if calculated_hash == msg_hash:
                    # Decrypt
                    key_bytes = self.symmetric_key.encode('utf-8')
                    decrypted = decrypt_message(encrypted_msg, key_bytes).decode('utf-8')
                    
                    self.root.after(0, lambda m=decrypted: self.log_message(f"📩 Client: {m}", "received"))
                else:
                    self.root.after(0, lambda: self.log_message("❌ Hash verification failed!", "error"))
                    
            except Exception as e:
                if self.running:
                    self.root.after(0, lambda: self.log_message(f"❌ Error: {str(e)}", "error"))
                break
                
        self.root.after(0, self.stop_server)
        
    def send_message(self):
        message = self.message_entry.get().strip()
        if not message:
            return
            
        self.message_entry.delete(0, tk.END)
        thread = threading.Thread(target=self._send_message_thread, args=(message,))
        thread.daemon = True
        thread.start()
        
    def _send_message_thread(self, message):
        try:
            self.root.after(0, lambda: self.log_message(f"📤 You: {message}", "sent"))
            
            # Encrypt
            key_bytes = self.symmetric_key.encode('utf-8')
            encrypted = encrypt_message(message.encode('utf-8'), key_bytes)
            msg_hash = self.hasher.hash_bytes(encrypted)
            
            # Send
            package = {'encrypted_msg': encrypted, 'hash': msg_hash}
            self.client_conn.send(pickle.dumps(package))
            
        except Exception as e:
            self.root.after(0, lambda: self.log_message(f"❌ Error: {str(e)}", "error"))
            
    def _update_running_ui(self):
        self.status_label.config(text="● Running", fg=self.success_color)
        self.start_btn.config(text="🛑 Stop Server", bg=self.error_color)
        self.port_entry.config(state=tk.DISABLED)
        
    def stop_server(self):
        self.running = False
        
        if self.client_conn:
            try:
                self.client_conn.close()
            except:
                pass
            self.client_conn = None
            
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
            self.server_socket = None
            
        self.status_label.config(text="● Stopped", fg=self.error_color)
        self.start_btn.config(text="🚀 Start Server", bg=self.success_color)
        self.port_entry.config(state=tk.NORMAL)
        self.message_entry.config(state=tk.DISABLED)
        self.send_btn.config(state=tk.DISABLED)
        
        self.rsa_indicator.config(text="⏳ Waiting...", fg="#6c7086")
        self.client_indicator.config(text="⏳ No connection", fg="#6c7086")
        
        self.log_message("\n🛑 Server stopped\n", "system")


def main():
    root = tk.Tk()
    app = SecureServerGUI(root)
    
    def on_closing():
        app.stop_server()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()