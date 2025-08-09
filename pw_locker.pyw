import json
import sqlite3
import tkinter as tk
import logging
from tkinter import messagebox as mb

import pyodbc
from Crypto.Random import get_random_bytes
from base64 import b64encode
from Crypto.Cipher import AES
import os
from pathlib import Path
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


# Function to insert a username, password, and key value into the local database when the user enters in a username
# and password values in their respected entry boxes and hits the 'Submit' button.
def insert_variable_into_table(user, password, key, result):
    success = True
    conn = None
    try:
        # Make a connection to the local db
        # Connect to SQL Server using SQL authentication
        server = os.getenv("server")
        database = os.getenv("database")
        username = os.getenv("username")
        password = os.getenv("password")

        conn = pyodbc.connect(
            f'DRIVER={{SQL Server}};SERVER={server};DATABASE={database};UID={username};PWD={password};Trusted_Connection=yes;autocommit=True;')
        cursor = conn.cursor()
        logging.info("Connected to SQLite")

        # SQL Server Insert query
        sql_insert_query = """
        INSERT INTO users (Username, Password, [Key], RESULT)
        VALUES (?, CONVERT(VARBINARY(MAX), ?), CONVERT(VARBINARY(MAX), ?), ?);
        """
        data = (user, password, key, result)

        # Execute and commit
        cursor.execute(sql_insert_query, data)
        conn.commit()
        logging.info("Python variables inserted successfully into SQL Server table")

        cursor.close()
        return success

    except pyodbc.Error as error:
        success = False
        logging.error("Failed to insert Python variable into SQL Server table", exc_info=True)
        mb.showerror('Failed', 'Failed to insert Python variable into SQL Server table')
        return success
    finally:
        if conn:
            conn.close()
            logging.info("SQL Server connection closed")


# Function to check if the Username field is blank
def user_pass_check_empty():
    success = True
    if UE.get() and PE.get():
        success = True
        return success
    elif not UE.get() and PE.get():
        logging.error("Failed: Input is required for Username")
        mb.showerror('Failed', 'Input is required for Username')
        success = False
        return success
    elif not PE.get() and UE.get():
        logging.error("Failed: Input is required for Password")
        mb.showerror('Failed', 'Input is required for Password')
        success = False
        return success
    else:
        success = False
        logging.error("Failed: Input is required for Username and Password")
        mb.showerror('Failed', 'Input is required for Username and Password')
        return success


'''
Function that does the following:
- Generates a byte key
- Gets the username and password info from the user
- Encrypts the password data 
- Run the insert_variable_into_table function to put the username, password, key info in the local database
- Writes variables needed to encrypt/decrypt the data to a file
- Clears out the username and password entry boxes
- Pop up occurs letting the user know the username and password successfully saved
'''


def set_data_to_db():
    try:
        # Generate the key
        key = get_random_bytes(32)

        # Check if username and password fields are empty
        success_check = user_pass_check_empty()
        if not success_check:
            success = False
        else:
            # Get and normalize user input
            user = UE.get().casefold()
            pw = PE.get()

            # === Encrypt password ===
            # Encrypt password
            pw_data = pw.encode('utf-8')
            cipher_encrypt = AES.new(key, AES.MODE_CFB)
            ct_bytes = cipher_encrypt.encrypt(pw_data)
            iv = b64encode(cipher_encrypt.iv).decode('utf-8')
            ct = b64encode(ct_bytes).decode('utf-8')  # This is your encrypted password as a string
            result = json.dumps({'iv': iv, 'ciphertext': ct})
            # Use ct directly — it's already a string
            ciphered_data = ct
            print(result)

            # Insert encrypted data into SQL Server
            success = insert_variable_into_table(user, ciphered_data, key, result)

        # Clear input fields
        UE.delete(0, tk.END)
        PE.delete(0, tk.END)

        # Show success message
        if success:
            mb.showinfo('Success', 'Data Successfully Saved')

    except Exception as e:
        logging.error("Something went wrong!", exc_info=True)
        mb.showerror('Failed', 'Something went wrong!')


######################################################################################################################
# GUI Layout
######################################################################################################################


win = tk.Tk()
win.geometry('300x250')  # Set window size
win.resizable(0, 0)  # Fix window
bullet = "\u2022"  # 'Bullet'/dot format

# Username Label and Entry Box
UL = tk.Label(win, text="Username: ")
UE = tk.Entry(win)

# Password Label and Entry Box
PL = tk.Label(win, text="Password: ")
PE = tk.Entry(win, show=bullet)  # Calling 'bullet' format to hide the password from being seen

# Submit and Exit buttons
SB = tk.Button(win, text="Submit", padx=10, command=set_data_to_db)
EB = tk.Button(win, text="Exit", padx=15, command=win.quit)  # Closes the program

# File Menu Bar
menu_bar = tk.Menu(win)
file_menu = tk.Menu(menu_bar, tearoff=0)
file_menu.add_command(label="Exit", command=win.quit)  # Closes the program
menu_bar.add_cascade(label="File", menu=file_menu)

# Win App Grid
UL.grid(row=0, column=0, padx=15, pady=40)
UE.grid(row=0, column=1, padx=15, pady=15)

PL.grid(row=1, column=0, padx=15, pady=15)
PE.grid(row=1, column=1, padx=15, pady=15)

EB.grid(row=3, column=1, columnspan=2, padx=105, pady=15)
SB.grid(row=3, column=0, columnspan=2, padx=5, pady=15)

# App Title
win.title("Password Locker")
# App Favicon
win.wm_iconbitmap("favicon.ico")
# File Menu Bar
win.config(menu=menu_bar)
# Win App Main Loop
win.mainloop()
