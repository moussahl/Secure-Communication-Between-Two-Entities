import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import socket
import pickle
import time
from rsa import RSA
from feistel import encrypt_message, decrypt_message
from hash_function import CustomHash


class SecureClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure Client - Encrypted Communication")
        self.root.geometry("700x700")
        self.root.resizable(True, True)
        
        # Colors
        self.bg_color = "#1e1e2e"
        self.fg_color = "#cdd6f4"
        self.accent_color = "#89b4fa"
        self.success_color = "#a6e3a1"
        self.error_color = "#f38ba8"
        self.panel_color = "#313244"
        
        self.root.configure(bg=self.bg_color)
        
        # Connection variables
        self.socket = None
        self.connected = False
        self.receiving = False
        self.rsa = RSA()
        self.server_public_key = None
        self.symmetric_key = "MySecurePassword123!"
        self.hasher = CustomHash()
        
        self.create_widgets()
        
    def create_widgets(self):
        """Create GUI elements"""
        
        # Title
        title_frame = tk.Frame(self.root, bg=self.bg_color)
        title_frame.pack(fill=tk.X, padx=20, pady=10)
        
        title_label = tk.Label(
            title_frame,
            text="🔐 Secure Client",
            font=("Arial", 24, "bold"),
            bg=self.bg_color,
            fg=self.accent_color
        )
        title_label.pack()
        
        subtitle_label = tk.Label(
            title_frame,
            text="Encrypted Client - Can Send & Receive Messages",
            font=("Arial", 10),
            bg=self.bg_color,
            fg=self.fg_color
        )
        subtitle_label.pack()
        
        # Connection Panel
        conn_frame = tk.LabelFrame(
            self.root,
            text="Connection",
            font=("Arial", 11, "bold"),
            bg=self.panel_color,
            fg=self.fg_color,
            relief=tk.RIDGE,
            bd=2
        )
        conn_frame.pack(fill=tk.X, padx=20, pady=5)
        
        addr_frame = tk.Frame(conn_frame, bg=self.panel_color)
        addr_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(
            addr_frame,
            text="Server:",
            font=("Arial", 10),
            bg=self.panel_color,
            fg=self.fg_color
        ).pack(side=tk.LEFT, padx=5)
        
        self.host_entry = tk.Entry(
            addr_frame,
            font=("Arial", 10),
            width=15,
            bg="#45475a",
            fg=self.fg_color
        )
        self.host_entry.insert(0, "127.0.0.1")
        self.host_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Label(
            addr_frame,
            text="Port:",
            font=("Arial", 10),
            bg=self.panel_color,
            fg=self.fg_color
        ).pack(side=tk.LEFT, padx=5)
        
        self.port_entry = tk.Entry(
            addr_frame,
            font=("Arial", 10),
            width=8,
            bg="#45475a",
            fg=self.fg_color
        )
        self.port_entry.insert(0, "9999")
        self.port_entry.pack(side=tk.LEFT, padx=5)
        
        self.connect_btn = tk.Button(
            addr_frame,
            text="🔌 Connect",
            font=("Arial", 10, "bold"),
            bg=self.accent_color,
            fg="#1e1e2e",
            command=self.toggle_connection,
            cursor="hand2",
            width=12
        )
        self.connect_btn.pack(side=tk.LEFT, padx=10)
        
        self.status_label = tk.Label(
            addr_frame,
            text="● Disconnected",
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
        
        self.rsa_indicator = self.create_indicator(enc_inner, "RSA", "🔒 Waiting...")
        self.feistel_indicator = self.create_indicator(enc_inner, "Feistel", "🔒 Waiting...")
        
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
        self.chat_display.tag_config("sent", foreground="#a6e3a1")
        self.chat_display.tag_config("received", foreground="#f5c2e7")
        self.chat_display.tag_config("error", foreground="#f38ba8")
        
        # Message Input
        input_frame = tk.Frame(self.root, bg=self.bg_color)
        input_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(
            input_frame,
            text="Message:",
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
            fg=self.fg_color
        )
        self.message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=8)
        self.message_entry.bind("<Return>", lambda e: self.send_message())
        
        self.send_btn = tk.Button(
            msg_frame,
            text="📤 Send Encrypted",
            font=("Arial", 11, "bold"),
            bg=self.success_color,
            fg="#1e1e2e",
            command=self.send_message,
            cursor="hand2",
            width=18,
            state=tk.DISABLED
        )
        self.send_btn.pack(side=tk.LEFT, padx=10)
        
        # Footer
        footer = tk.Label(
            self.root,
            text="🔐 Client: Sends & receives encrypted messages using RSA + Feistel + SHA-256",
            font=("Arial", 8),
            bg=self.bg_color,
            fg="#6c7086"
        )
        footer.pack(pady=5)
        
    def create_indicator(self, parent, label, status):
        frame = tk.Frame(parent, bg=self.panel_color)
        frame.pack(side=tk.LEFT, padx=25)
        
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
        
    def toggle_connection(self):
        if self.connected:
            self.disconnect()
        else:
            self.connect()
    
    def connect(self):
        host = self.host_entry.get()
        port = int(self.port_entry.get())
        
        self.log_message(f"🔌 Connecting to {host}:{port}...", "system")
        thread = threading.Thread(target=self._connect_thread, args=(host, port))
        thread.daemon = True
        thread.start()
        
    def _connect_thread(self, host, port):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            
            self.root.after(0, lambda: self.log_message("✓ Connected!\n", "system"))
            
            # Receive public key
            self.root.after(0, lambda: self.log_message("📥 Receiving RSA public key...", "system"))
            self.server_public_key = pickle.loads(self.socket.recv(4096))
            self.root.after(0, lambda: self.log_message("✓ Public key received", "system"))
            self.root.after(0, lambda: self.rsa_indicator.config(text="✓ Exchanged", fg=self.success_color))
            
            # Send symmetric key
            self.root.after(0, lambda: self.log_message("📤 Sending symmetric key...", "system"))
            encrypted_key = self.rsa.encrypt(self.symmetric_key, self.server_public_key)
            self.socket.send(pickle.dumps(encrypted_key))
            self.root.after(0, lambda: self.log_message("✓ Symmetric key sent", "system"))
            self.root.after(0, lambda: self.feistel_indicator.config(text="✓ Ready", fg=self.success_color))
            
            self.connected = True
            self.receiving = True
            self.root.after(0, self._update_connected_ui)
            
            self.root.after(0, lambda: self.log_message("="*60 + "\n✅ SECURE CHANNEL ESTABLISHED\n" + "="*60 + "\n", "system"))
            
            # Start receiving thread
            receive_thread = threading.Thread(target=self._receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
        except Exception as e:
            self.root.after(0, lambda: self.log_message(f"❌ Error: {str(e)}", "error"))
            self.root.after(0, lambda: messagebox.showerror("Connection Error", str(e)))
            
    def _receive_messages(self):
        """Continuously receive messages from server"""
        while self.receiving and self.connected:
            try:
                data = self.socket.recv(8192)
                if not data:
                    break
                
                package = pickle.loads(data)
                encrypted_msg = package['encrypted_msg']
                msg_hash = package['hash']
                
                # Verify and decrypt
                calculated_hash = self.hasher.hash_bytes(encrypted_msg)
                
                if calculated_hash == msg_hash:
                    key_bytes = self.symmetric_key.encode('utf-8')
                    decrypted = decrypt_message(encrypted_msg, key_bytes).decode('utf-8')
                    self.root.after(0, lambda m=decrypted: self.log_message(f"📩 Server: {m}", "received"))
                else:
                    self.root.after(0, lambda: self.log_message("❌ Hash verification failed!", "error"))
                    
            except Exception as e:
                if self.receiving:
                    self.root.after(0, lambda: self.log_message(f"❌ Connection lost", "error"))
                break
                
        self.root.after(0, self.disconnect)
        
    def _update_connected_ui(self):
        self.status_label.config(text="● Connected", fg=self.success_color)
        self.connect_btn.config(text="🔌 Disconnect", bg=self.error_color)
        self.send_btn.config(state=tk.NORMAL)
        self.host_entry.config(state=tk.DISABLED)
        self.port_entry.config(state=tk.DISABLED)
        
    def disconnect(self):
        self.receiving = False
        self.connected = False
        
        if self.socket:
            try:
                self.socket.send(b'EXIT')
                self.socket.close()
            except:
                pass
            self.socket = None
        
        self.status_label.config(text="● Disconnected", fg=self.error_color)
        self.connect_btn.config(text="🔌 Connect", bg=self.accent_color)
        self.send_btn.config(state=tk.DISABLED)
        self.host_entry.config(state=tk.NORMAL)
        self.port_entry.config(state=tk.NORMAL)
        
        self.rsa_indicator.config(text="🔒 Waiting...", fg="#6c7086")
        self.feistel_indicator.config(text="🔒 Waiting...", fg="#6c7086")
        
        self.log_message("\n🔌 Disconnected\n", "system")
        
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
            self.socket.send(pickle.dumps(package))
            
        except Exception as e:
            self.root.after(0, lambda: self.log_message(f"❌ Error: {str(e)}", "error"))


def main():
    root = tk.Tk()
    app = SecureClientGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()