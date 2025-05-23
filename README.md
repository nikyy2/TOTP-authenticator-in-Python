# 🔐 TOTP Authenticator GUI (Python)

A desktop-based TOTP Authenticator made with Python and `customtkinter` (GUI). This tool allows you to generate time-based OTP codes (TOTP) for your accounts, similar to Google Authenticator, but on your desktop. You can add secrets manually or by scanning a QR code image.

---

## 📦 Features

- 🔐 Local TOTP code generation (no internet required)
- ➕ Add accounts manually using Base32-encoded secrets
- 📷 Add accounts via QR code image (TOTP-compatible)
- ➖ Remove accounts fast
- ⏳ Animated circular timer showing code refresh
- 💾 Saves secrets locally in `secrets.json`

---

## ✅ Requirements

Make sure you have **Python 3.8 or later** installed.

Install all required packages using:

```bash
pip install -r requirements.txt
```

### `requirements.txt` contents:
```
customtkinter
Pillow
pyzbar
qrcode
```

---

## 🚀 How to Use

### 1. Run the App

```bash
python your_script_name.py
```

Replace `your_script_name.py` with your actual file name (e.g. `authenticator.py`).

---

### 2. Add a New Account (Manual)

- Click the **➕ Add new** button.
- Enter the **account name**.
- Enter the **Base32-encoded secret key** (e.g., from a site like Discord, GitHub, or Google).

---

### 3. Add a New Account by Scanning a QR Code

- Click the **📷 Add new by QR** button.
- Enter an **account name**.
- Select an **image file** containing a QR code (formats supported: PNG, JPG, BMP, etc).
- The secret key will be extracted from the image.

> ✅ **Tips:**  
> - Use a **clear and readable** QR image.  
> - Avoid blurry, low-resolution, or compressed images.  
> - The QR must be in standard `otpauth://` format.

---

### 4. Remove an Account

- Click **➖ Remove account**.
- Type the **exact account name** to remove.

---

### 5. View OTP Codes

- Accounts and their current OTP codes appear in a scrollable list.
- Codes refresh every 30 seconds.
- A circular visual indicator shows how much time is left.

---

## 📁 Data Storage

Secrets are saved to a file called:

```
secrets.json
```

Each entry contains the account name and its associated secret.

> ⚠️ **Warning:** This file is stored in plain text. Do **not** upload it to GitHub or share it publicly.

---

## 📸 Generate a Test QR Code (Optional)

For demonstration, you can generate your own QR code with a fake secret like this:

```python
import qrcode

secret = "JBSWY3DPEHPK3PXP"  # example Base32 key
issuer = "ExampleApp"
account = "demo@example.com"
uri = f"otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}"

img = qrcode.make(uri)
img.save("demo_qr.png")
```

Use this generated image (`.png`) to test the "Add by QR" feature.

---

## ⚠️ Disclaimer

This project is intended for **educational and demonstration purposes only**.

- Secrets are stored **unencrypted** in plain text (`secrets.json`).
- This tool is **not** intended for production or highly secure environments.
- Do **not** use it to store real 2FA credentials for critical accounts.

---

## 📚 License

This project is released under the **MIT License**. Feel free to modify or use it with attribution.

---

## 👨‍💻 Author

Created by **nikyy2**.  
Feedback and contributions are welcome!
