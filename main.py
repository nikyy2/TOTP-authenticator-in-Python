import os
import json
import time
import base64
import struct
import hashlib
import hmac
import customtkinter as ctk
import tkinter as tk
from tkinter import Canvas, filedialog, messagebox, simpledialog
from PIL import Image
from pyzbar.pyzbar import decode
from urllib.parse import parse_qs, urlparse


SECRETS_FILE      = "secrets.json"
TOTP_INTERVAL     = 30        # seconds per cycle
ANIMATION_INTERVAL = 100      # ms between updates
DIALOG_WIDTH      = 400       # width of custom input dialog
DIALOG_HEIGHT     = 150       # height of custom input dialog


class LargeInputDialog(ctk.CTkToplevel):
    def __init__(self, parent, title, prompt):
        super().__init__(parent)
        self.title(title)
        self.geometry(f"{DIALOG_WIDTH}x{DIALOG_HEIGHT}")
        self.resizable(False, False)
        self.result = None

        ctk.CTkLabel(self, text=prompt, anchor="w").pack(
            fill="x", padx=20, pady=(20, 5)
        )
        self.entry = ctk.CTkEntry(self)
        self.entry.pack(fill="x", padx=20, pady=(0, 20))
        self.entry.focus()

        btn_frame = ctk.CTkFrame(self)
        btn_frame.pack(fill="x", padx=20, pady=(0, 10))
        ctk.CTkButton(btn_frame, text="OK", command=self._on_ok).pack(side="right", padx=5)
        ctk.CTkButton(btn_frame, text="Cancel", command=self.destroy).pack(side="right")

        self.transient(parent)
        self.grab_set()
        parent.wait_window(self)

    def _on_ok(self):
        self.result = self.entry.get().strip()
        self.destroy()


def load_secrets():
    if not os.path.exists(SECRETS_FILE):
        return {}
    with open(SECRETS_FILE, "r") as f:
        return json.load(f)


def save_secrets(secrets):
    with open(SECRETS_FILE, "w") as f:
        json.dump(secrets, f, indent=4)


def generate_totp(secret, interval=TOTP_INTERVAL, digits=6):
    """
    TOTP code from a base32-encoded.
    """
    key     = base64.b32decode(secret.strip().replace(" ", "").upper(), casefold=True)
    counter = struct.pack(">Q", int(time.time() // interval))
    digest  = hmac.new(key, counter, hashlib.sha1).digest()
    offset  = digest[-1] & 0x0F
    code    = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10**digits)).zfill(digits)


def extract_secret_from_qr(path):
    img     = Image.open(path)
    decoded = decode(img)
    if not decoded:
        raise ValueError("no QR code found")
    uri     = decoded[0].data.decode("utf-8")
    params  = parse_qs(urlparse(uri).query)
    secret  = params.get("secret", [""])[0]
    if not secret:
        raise ValueError("no 'secret' in QR")
    return secret


class AuthenticatorApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("TOTP Authenticator | nikyy2")
        self.geometry("420x620")
        self.resizable(False, False)

        self.secrets     = load_secrets()
        self.code_labels = {}  # map account → label widget

        self._build_ui()
        self._start_loops()

    def _prompt(self, title, prompt):
        dlg = LargeInputDialog(self, title, prompt)
        return dlg.result

    def _build_ui(self):
        # background
        mode     = ctk.get_appearance_mode()
        bg_color = "#1f1f1f" if mode == "Dark" else "#f0f0f0"

        # cooldown circle
        top = ctk.CTkFrame(self, fg_color=bg_color)
        top.pack(pady=20)
        self.canvas = Canvas(top, width=150, height=150, bg=bg_color, highlightthickness=0)
        self.canvas.pack()
        self.canvas.create_oval(10, 10, 140, 140, outline="#444", width=10)
        self.arc = self.canvas.create_arc(10, 10, 140, 140,
                                          start=90, extent=0,
                                          style="arc", outline="#1abc9c", width=10)

        # buttons
        btn_frame = ctk.CTkFrame(self)
        btn_frame.pack(fill="x", padx=20, pady=(0, 10))
        ctk.CTkButton(btn_frame, text="➕ Add new",        command=self._on_add,    width=100).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="➖ Remove account", command=self._on_remove, width=100).pack(side="left", padx=5)
        ctk.CTkButton(btn_frame, text="📷  Add new by QR", command=self._on_scan,   width=100).pack(side="left", padx=5)

        # scroll
        self.list_frame = ctk.CTkScrollableFrame(self)
        self.list_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        self._refresh_account_list()

    def _refresh_account_list(self):
        # clear old widgets
        for child in self.list_frame.winfo_children():
            child.destroy()

        # rebuild rows
        self.code_labels.clear()
        for name, secret in self.secrets.items():
            row = ctk.CTkFrame(self.list_frame, fg_color="#222")
            row.pack(fill="x", pady=5)

            ctk.CTkLabel(row, text=name, font=ctk.CTkFont(size=14)).pack(side="left", padx=10, pady=10)
            lbl = ctk.CTkLabel(row, text=generate_totp(secret),
                              font=ctk.CTkFont(size=18, weight="bold"),
                              text_color="#1abc9c")
            lbl.pack(side="right", padx=10, pady=10)
            self.code_labels[name] = lbl

    def _on_add(self):
        name   = self._prompt("Add Account",     "Account name:")
        if not name:
            return
        secret = self._prompt("Base32 Secret",   "Enter your secret:")
        if not secret:
            return

        try:
            # validate secret
            base64.b32decode(secret.strip().replace(" ", "").upper(), casefold=True)
        except Exception:
            messagebox.showerror("Invalid Secret", "That does not look like Base32.")
            return

        self.secrets[name] = secret.strip().replace(" ", "")
        save_secrets(self.secrets)
        self._refresh_account_list()

    def _on_remove(self):
        if not self.secrets:
            messagebox.showinfo("Info", "No accounts to remove.")
            return

        name = self._prompt("Remove Account", "Enter name to remove:")
        if not name or name not in self.secrets:
            messagebox.showerror("Not Found", f"No account named '{name}'.")
            return

        del self.secrets[name]
        save_secrets(self.secrets)
        self._refresh_account_list()

    def _on_scan(self):
        # account name
        name = self._prompt("Scan QR", "Account name:")
        if not name:
            return

        # pick image
        path = filedialog.askopenfilename(
            parent=self,
            title="Select QR image",
            filetypes=[("Images", "*.png;*.jpg;*.jpeg;*.bmp;*.gif"), ("All", "*.*")]
        )
        if not path:
            return

        try:
            secret = extract_secret_from_qr(path)
        except Exception as e:
            messagebox.showerror("Scan Failed", str(e))
            return

        self.secrets[name] = secret
        save_secrets(self.secrets)
        self._refresh_account_list()
        messagebox.showinfo("Success", f"Added '{name}' from {os.path.basename(path)}")

    def _update_codes(self):
        # refresh labels once per cycle
        for name, secret in self.secrets.items():
            lbl = self.code_labels.get(name)
            if lbl:
                lbl.configure(text=generate_totp(secret))
        # next refresh
        self.after(TOTP_INTERVAL * 1000, self._update_codes)

    def _update_circle(self):
        # draining arc
        remaining = TOTP_INTERVAL - (time.time() % TOTP_INTERVAL)
        angle     = (remaining / TOTP_INTERVAL) * 360
        self.canvas.itemconfigure(self.arc, extent=-angle)
        self.after(ANIMATION_INTERVAL, self._update_circle)

    def _start_loops(self):
        self._update_codes()
        self._update_circle()


if __name__ == "__main__":
    os.system("cls")
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("green")
    app = AuthenticatorApp()
    app.mainloop()
