import pandas as pd
import string
import random
from Univ_pass import gen_pass

df = pd.read_csv(r'wordlist/AWordBank.csv')
Wordbank = df['wordbank']
alphabet = string.ascii_letters + string.digits
angka = string.digits
simbol = ['!', '*', '$', '#', '?']


def acak(X):
    hasil = random.choice(X)
    return hasil


def getresult(nilai):
    result = [item for item in Wordbank if len(str(item)) == nilai]
    return result
