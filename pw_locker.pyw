import json
import tkinter as tk
import logging
from tkinter import messagebox as mb
import pyodbc
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
import os
from pathlib import Path
from dotenv import load_dotenv

# Logging setup
logging.basicConfig(filename='activity.log',
                    level=logging.DEBUG,
                    format='%(asctime)s : %(levelname)s : %(message)s')
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger('').addHandler(console)

# Load environment variables
env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path, override=True)
print("Loaded credentials:")
print("Server:", os.getenv("server"))
print("Database:", os.getenv("database"))
print("Username:", os.getenv("db_username"))
print("Password:", os.getenv("db_password"))
logging.debug(f"Loaded username: {os.getenv('db_username')}")

# Validate required keys
required_keys = ["server", "database", "db_username", "db_password"]
for key in required_keys:
    if not os.getenv(key):
        logging.error(f"Missing .env key: {key}")
        raise EnvironmentError(f"Missing .env key: {key}")

# SQL Server upsert logic
def upsert_variable_into_table(user, password, key, result):
    success = True
    conn = None
    try:
        server = os.getenv("server")
        database = os.getenv("database")
        username = os.getenv("db_username")
        password_env = os.getenv("db_password")

        conn = pyodbc.connect(
            f'DRIVER={{SQL Server}};SERVER={server};DATABASE={database};UID={username};PWD={password_env};')
        cursor = conn.cursor()
        logging.info("Connected to SQL Server")

        sql_upsert_query = """
        MERGE INTO users AS target
        USING (SELECT ? AS Username) AS source
        ON target.Username = source.Username
        WHEN MATCHED THEN
            UPDATE SET Password = ?, [Key] = ?, RESULT = ?
        WHEN NOT MATCHED THEN
            INSERT (Username, Password, [Key], RESULT)
            VALUES (source.Username, ?, ?, ?);
        """

        data = (user, password, key, result, password, key, result)
        logging.debug(f"SQL payload: {data}")
        cursor.execute(sql_upsert_query, data)
        conn.commit()
        cursor.close()
        logging.info(f"Upserted user: {user}")
        return success

    except pyodbc.Error as error:
        success = False
        logging.error("Failed to upsert user into SQL Server", exc_info=True)
        mb.showerror('Failed', 'Failed to save user data to SQL Server')
        return success
    finally:
        if conn:
            conn.close()
            logging.info("SQL Server connection closed")

# Input validation
def user_pass_check_empty():
    if UE.get() and PE.get():
        return True
    elif not UE.get() and PE.get():
        logging.error("Input is required for Username")
        mb.showerror('Failed', 'Input is required for Username')
    elif not PE.get() and UE.get():
        logging.error("Input is required for Password")
        mb.showerror('Failed', 'Input is required for Password')
    else:
        logging.error("Input is required for Username and Password")
        mb.showerror('Failed', 'Input is required for Username and Password')
    return False

# Encrypt and save data
def set_data_to_db():
    try:
        if not user_pass_check_empty():
            return

        user = UE.get().casefold()
        pw = PE.get()
        key = get_random_bytes(32)

        pw_data = pw.encode('utf-8')
        cipher_encrypt = AES.new(key, AES.MODE_CFB)
        ct_bytes = cipher_encrypt.encrypt(pw_data)
        iv = b64encode(cipher_encrypt.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps({'iv': iv, 'ciphertext': ct})

        ciphered_data = ct.encode('utf-8')
        key_bytes = key

        success = upsert_variable_into_table(user, ciphered_data, key_bytes, result)

        UE.delete(0, tk.END)
        PE.delete(0, tk.END)

        if success:
            mb.showinfo('Success', f'Data saved for user: {user}')

    except Exception as e:
        logging.error("Unexpected error in set_data_to_db", exc_info=True)
        mb.showerror('Failed', 'Something went wrong!')

######################################################################################################################
# GUI Layout
######################################################################################################################

win = tk.Tk()
win.geometry('300x250')
win.resizable(0, 0)
bullet = "\u2022"

UL = tk.Label(win, text="Username: ")
UE = tk.Entry(win)

PL = tk.Label(win, text="Password: ")
PE = tk.Entry(win, show=bullet)

SB = tk.Button(win, text="Submit", padx=10, command=set_data_to_db)
EB = tk.Button(win, text="Exit", padx=15, command=win.quit)

menu_bar = tk.Menu(win)
file_menu = tk.Menu(menu_bar, tearoff=0)
file_menu.add_command(label="Exit", command=win.quit)
menu_bar.add_cascade(label="File", menu=file_menu)

UL.grid(row=0, column=0, padx=15, pady=40)
UE.grid(row=0, column=1, padx=15, pady=15)
PL.grid(row=1, column=0, padx=15, pady=15)
PE.grid(row=1, column=1, padx=15, pady=15)
EB.grid(row=3, column=1, columnspan=2, padx=105, pady=15)
SB.grid(row=3, column=0, columnspan=2, padx=5, pady=15)

win.title("Password Locker")
win.wm_iconbitmap("favicon.ico")
win.config(menu=menu_bar)
win.mainloop()