import logging
import json
import sqlite3
from pathlib import Path

import pyodbc
import sys
import pyperclip
from base64 import b64decode
from Crypto.Cipher import AES
import os
from dotenv import load_dotenv

# Logging configurations
logging.basicConfig(filename='activity.log',
                    level=logging.DEBUG,
                    format='%(asctime)s : %(levelname)s : %(message)s')

# define a Handler which writes INFO messages or higher to the sys.stderr
console = logging.StreamHandler()
console.setLevel(logging.INFO)
# add the handler to the root logger
logging.getLogger('').addHandler(console)

# Activate '.env' file
load_dotenv()
load_dotenv(verbose=True)
env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path)

def select_all_passwords():
    try:
        # Connect to SQL Server using SQL authentication
        server = os.getenv("server")
        database = os.getenv("database")
        username = os.getenv("username")
        password = os.getenv("password")

        conn = pyodbc.connect(
            f'DRIVER={{SQL Server}};SERVER={server};DATABASE={database};UID={username};PWD={password};Trusted_Connection=yes;autocommit=True;')
        cursor = conn.cursor()
        logging.info("Connected to SQL Server")

        select_user = "SELECT Username, Password, [Key], Result FROM users;"
        cursor.execute(select_user)
        logging.info("Query executed successfully")

        db_users_all = cursor.fetchall()
        cursor.close()
        conn.close()
        logging.info("SQL Server connection closed")

        # === Decrypt ===
        l_users = []
        decrypt_pw = []
        for username, pw, key, results in db_users_all:
            l_users.append(username)
            b64 = json.loads(results)
            ct = b64decode(b64['ciphertext'])
            iv = b64decode(b64['iv'])
            cipher_decrypt = AES.new(key, AES.MODE_CFB, iv=iv)
            dec_pw = cipher_decrypt.decrypt(ct)
            dpw = dec_pw.decode('utf-8')
            decrypt_pw.append(dpw)

        PASSWORDS = {k: v for k, v in zip(l_users, decrypt_pw)}
        return PASSWORDS

    except pyodbc.Error as error:
        logging.error("Failed to read from SQL Server", exc_info=True)




# Set the variable PASSWORDS to the dictionary returned from the select_all_passwords function.
PASSWORDS = select_all_passwords()

# If the 'run' argument is less than 2 characters, explain the process to the user.
if len(sys.argv) < 2:
    print('Usage: python pw.py[account] - copy account password')
    sys.exit()

# Set the account variable to the second argument
account = sys.argv[1].lower()  # first command line arg is account name


try:
    # If the second argument is a key is the PASSWORDS dictionary, copy its value, the decrypted password for the user.
    if account in PASSWORDS:
        pyperclip.copy(PASSWORDS[account])
        print('Password for {} copied to clipboard.'.format(sys.argv[1]))
    else:
        print('There is no account named {}.'.format(sys.argv[1]))
except Exception as e:
    logging.exception(e.args)
    print("Cannot process your request at this time.")
