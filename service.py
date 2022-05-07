import pandas as pd
import string
import random
import secrets


df = pd.read_csv(r'wordlist/AWordBank.csv')
Wordbank = df['wordbank']
alphabet = string.ascii_letters + string.digits
angka = string.digits
simbol = ['!', '*', '$', '#', '?']


PassBank = pd.read_csv('rockyou/pass_bank.csv')
New_PassBank = PassBank['PassBank']
gen_pass = New_PassBank


def acak(X):
    hasil = random.choice(X)
    return hasil


def getresult(nilai):
    result = [item for item in Wordbank if len(str(item)) == nilai]
    return result


def new_angka():
    new_angka = acak(angka)
    return new_angka


def new_simbol():
    new_simbol = acak(simbol)
    return new_simbol
