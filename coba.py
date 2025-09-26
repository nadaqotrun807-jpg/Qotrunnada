import streamlit as st
from math import gcd

# Fungsi enkripsi
def affine_encrypt(plaintext, a, b):
    ciphertext = ''
    for char in plaintext:
        if char.isalpha():
            base = ord('a') if char.islower() else ord('A')
            c = chr(((a * (ord(char) - base) + b) % 26) + base)
            ciphertext += c
        else:
            ciphertext += char
    return ciphertext


# Fungsi mencari invers modulo a^-1 mod 26
def mod_inverse(a, m=26):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


# Fungsi dekripsi
def affine_decrypt(ciphertext, a, b):
    plaintext = ''
    a_inv = mod_inverse(a, 26)
    if a_inv is None:
        return "Tidak ada invers dari a, dekripsi gagal."

    for char in ciphertext:
        if char.isalpha():
            base = ord('a') if char.islower() else ord('A')
            p = chr(((a_inv * ((ord(char) - base) - b)) % 26) + base)
            plaintext += p
        else:
            plaintext += char
    return plaintext


# Fungsi cek coprime
def is_coprime(a, m=26):
    return gcd(a, m) == 1


# Streamlit UI
st.title("🔐 Affine Cipher: Enkripsi & Dekripsi")

# Input form
mode = st.radio("Pilih Mode", ("Enkripsi", "Dekripsi"))

text = st.text_input("Masukkan Teks", "")
a = st.number_input("Masukkan kunci a (coprime dengan 26)", min_value=1, step=1)
b = st.number_input("Masukkan kunci b", min_value=0, step=1)

if st.button("Proses"):
    if not is_coprime(int(a)):
        st.error("Kunci 'a' harus coprime dengan 26 agar proses valid.")
    else:
        if mode == "Enkripsi":
            hasil = affine_encrypt(text, int(a), int(b))
            st.success(f"Ciphertext: {hasil}")
        else:
            hasil = affine_decrypt(text, int(a), int(b))
            st.success(f"Plaintext: {hasil}")
