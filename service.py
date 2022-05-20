import pandas as pd
import string
import random
import secrets

alphabet = string.ascii_letters + string.digits
angka = string.digits
simbol = ['!', '*', '$', '#', '?']


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
