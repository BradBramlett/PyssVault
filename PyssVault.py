#!/bin/python3
import pandas as pd
from getpass import getpass, getuser
from cryptography.fernet import Fernet
from hashlib import sha256
from pyperclip import copy
import base64, os, warnings

#Dictionary where hashes will be stored.
vault = {}

#Options given to choose what action to utilize.
actions = ['Add', 'Search', 'Remove', 'Quit']

#Path to Excel File hashes are saved to via OS. 
def get_file():
    try:
        uname = os.uname()
    except:
        uname = 'Windows'
    if 'Linux' in uname:
        file = ("/home/" + getuser() + "/.local/vault.xlsx")
    elif 'Darwin' in uname:
        file = ('/Users/' + getuser() + "/.local/vault.xlsx" )
    elif uname == 'Windows':
        file = ('C:\\Users\\' + getuser() + '\\AppData\\Local\\vault.xlsx')
    return file

#Clears the screen for cleaner interface.
def clear_screen():
    try:
        os.uname()
        os.system('clear')
    except:
        os.system('cls')



#Asks for user input, and encrypts the input and returns the hash of the input to be saved in vault. 
def encrypt(f):
    message = f.encrypt(getpass("Password to be encrypted: ").encode())
    return message.decode()

#Uses vault_key to decrypt the stored password in the vault.
def decrypt(Hash,f_key):
    try:
        passwd = f_key.decrypt(Hash).decode()
        return passwd
    except:
        print('\n\nInvalid Key\n\n')
        exit()

#Reads the stored Excel File to grab all the stored hashes. Each Sheet is an individual domain/site.
def read_excel(file):
    try:
        xl = pd.ExcelFile(file)
        domains = xl.sheet_names
        for domain in domains:
            df = pd.DataFrame()
            df['Passwords'] = pd.read_excel(file, header=None,sheet_name=domain, usecols='A')
            vault[domain] = {}
            vault[domain]['Passwords'] = df['Passwords'].values.tolist()
    except:
        pass

#Creates list of domains to choose which password you want to get the password for. 
def list_domains():
    keys = list(vault.keys())
    counter = 1
    if keys == []:
        print('\nNo stored passwords\n')
        exit()
    for key in keys:
        print(str(counter) + ") " + key)
        counter += 1
    print('\n')
    Selection = keys[int(input('\nSelection: ')) -1]
    return Selection

#Adds password hash to vault. 
def add(f_key):
    domain = input("\nDomain: ")
    username = input("\nUsername: ")
    key = str(domain + " - " + username)
    if key in vault.keys():
        vault[key]['Passwords'].append(encrypt(f_key))
        vault[key]['Passwords'].reverse()
    else:
        vault[key] = {}
        vault[key]['Passwords'] = []
        vault[key]['Passwords'].append(encrypt(f_key))

#Creates, updates/rewrites excel. 
def write_excel(file):
    warnings.filterwarnings('ignore', category=UserWarning, module='openpyxl')
    keys = list(vault.keys())
    if keys == []:
        df = pd.DataFrame()
        df.to_excel(file)
    else:
        for i in keys:
            df = pd.DataFrame(vault[i])
            if keys.index(i) == 0:
                df.to_excel(file, sheet_name=i, index=False, header=False)
            else:
                with pd.ExcelWriter(file, mode='a') as writer:
                    df.to_excel(writer, sheet_name=i, index=False, header=False)



#Lists the most recent password for chosen Domain. Also, allows user to get full saved history for domain if need be. 
def Search(f_key):
    Selection = list_domains()
    for passwd in vault[Selection]['Passwords']:
        hash = passwd.encode()
        if vault[Selection]['Passwords'].index(passwd) == 0:
            hash = decrypt(hash,f_key)
            print('\nPassword: '+ hash+'\n')
            copy(hash)
            print('Password Copied to clipboard')
            if len(vault[Selection]['Passwords']) > 1:
                print("\n\nMore Entries Available for this domain.\n\n")
                Selection2 = str.upper(input('Show Other Passwords associated with Domain? Y/N: '))
                if "Y" in Selection2:
                    print('\n')
                    for i in vault[Selection]['Passwords'][1::]:
                        i = i.encode()
                        print(decrypt(i)+'\n')
                else:
                    exit()

#Allows user to remove a password entry from domain. Deletes empty domain as well. 
def Remove():
    Selection1 = list_domains()
    counter = 1
    for passwd in vault[Selection1]['Passwords']:
        print(str(counter) + ') ' + decrypt(passwd.encode()))
        counter +=1
    Selection2 = int(input("\nRemove Entry: ")) - 1
    vault[Selection1]['Passwords'].remove(vault[Selection1]['Passwords'][Selection2])
    if vault[Selection1]['Passwords'] == []:
        del vault[Selection1]
    return vault

def main():
    clear_screen()    
#Takes given passphrase, converts it to sha256 hash, and base64 encodes hash. Creates symmetric key for 
#encrypting and decrypting stored hashes in the vault. 
    password = sha256(getpass("PassKey used for Encrypting/Decrypting: ").encode()).digest()
    vault_key = base64.urlsafe_b64encode(password)
    f_key = Fernet(vault_key)
    file = get_file()
    read_excel(file)
    counter = 1
    print('\n')
    for action in actions:
        print(str(counter) + ") " + action)
        counter += 1
    print('\n')
    selection = actions[int(input('Selection: ')) - 1]
    print('\n')
    if selection == 'Add':
        add(f_key)
        write_excel(file)
    elif selection == 'Search':
        Search(f_key)
    elif selection == 'Remove':
        Remove()
        write_excel(file)
    elif selection == 'Quit':
        exit()
main()
