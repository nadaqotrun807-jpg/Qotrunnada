import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import time
import pandas as pd

# =========================
# FUNGSI UTILITAS
# =========================

def generate_rsa_keypair(bits: int = 2048):
    key = RSA.generate(bits)
    return key.export_key().decode(), key.publickey().export_key().decode()


# =========================
# ENKRIPSI RSA (FULL TIME)
# =========================
def rsa_encrypt_oaep(plaintext: str, public_key_pem: str):
    t_start = time.perf_counter()

    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    plaintext_bytes = plaintext.encode("utf-8")

    ciphertext_bytes = cipher.encrypt(plaintext_bytes)

    t_end = time.perf_counter()

    return ciphertext_bytes.hex(), (t_end - t_start)


# =========================
# DEKRIPSI RSA (FULL TIME)
# =========================
def rsa_decrypt_oaep(ciphertext_hex: str, private_key_pem: str):
    t_start = time.perf_counter()

    private_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)

    plaintext_bytes = cipher.decrypt(ciphertext_bytes)

    t_end = time.perf_counter()

    return plaintext_bytes.decode("utf-8"), (t_end - t_start)


# =========================
# STREAMLIT APP
# =========================

st.set_page_config(page_title="RSA Tunggal – Uji Waktu")

st.title("RSA Tunggal (OAEP-SHA256) – Enkripsi, Dekripsi & Pengujian Waktu")

# =========================
# GENERATE KEY SEKALI
# =========================
if "private_key" not in st.session_state:
    priv, pub = generate_rsa_keypair()
    st.session_state.private_key = priv
    st.session_state.public_key = pub

rsa_priv = RSA.import_key(st.session_state.private_key)
rsa_pub = RSA.import_key(st.session_state.public_key)

# =========================
# PARAMETER RSA
# =========================
st.subheader("Parameter RSA")

st.write("Modulus (n):")
st.code(str(rsa_pub.n))

st.write("Eksponen publik (e):")
st.code(str(rsa_pub.e))

st.write("Eksponen privat (d):")
st.code(str(rsa_priv.d))

st.write("Bilangan prima p:")
st.code(str(rsa_priv.p))

st.write("Bilangan prima q:")
st.code(str(rsa_priv.q))

st.divider()

# =========================
# ENKRIPSI
# =========================
st.subheader("Enkripsi RSA")

plaintext = st.text_area("Plaintext", "Contoh pesan RSA")
N = st.number_input("Jumlah uji", 1, 100, 5)

if st.button("ENKRIPSI"):
    hasil = []

    ciphertext_hex, _ = rsa_encrypt_oaep(plaintext, st.session_state.public_key)

    for i in range(N):
        _, t = rsa_encrypt_oaep(plaintext, st.session_state.public_key)
        hasil.append({"Uji": i+1, "Waktu Enkripsi": t})

    df = pd.DataFrame(hasil)
    rata = df["Waktu Enkripsi"].mean()

    st.success("Enkripsi selesai")
    st.code(ciphertext_hex)

    st.dataframe(df)
    st.info(f"Rata-rata waktu: {rata:.6f} detik")

st.divider()

# =========================
# DEKRIPSI
# =========================
st.subheader("Dekripsi RSA")

cipher_input = st.text_area("Ciphertext (hex)")
N_dec = st.number_input("Jumlah uji dekripsi", 1, 100, 5, key="dec")

if st.button("DEKRIPSI"):
    try:
        plaintext_out, _ = rsa_decrypt_oaep(cipher_input, st.session_state.private_key)
        st.success("Dekripsi berhasil")
        st.code(plaintext_out)

        hasil = []
        for i in range(N_dec):
            _, t = rsa_decrypt_oaep(cipher_input, st.session_state.private_key)
            hasil.append({"Uji": i+1, "Waktu Dekripsi": t})

        df = pd.DataFrame(hasil)
        rata = df["Waktu Dekripsi"].mean()

        st.dataframe(df)
        st.info(f"Rata-rata waktu: {rata:.6f} detik")

    except Exception as e:
        st.error(f"Gagal: {e}")
