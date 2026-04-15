import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import time
import pandas as pd

# =========================
# FUNGSI UTILITAS AES
# =========================
def derive_key_from_password(password: str) -> bytes:
    """
    Mengubah password menjadi kunci AES 128-bit menggunakan SHA-256
    """
    if not password:
        raise ValueError("Password tidak boleh kosong.")
    sha256_hash = hashlib.sha256(password.encode("utf-8")).digest()
    return sha256_hash[:16]  # 128-bit


# =========================
# ENKRIPSI AES (FIXED)
# =========================
def aes_encrypt_cbc(plaintext: str, password: str):
    """
    Enkripsi AES-128 CBC + PKCS7
    Output: ciphertext_hex, iv_hex, elapsed_time
    """

    t_start = time.perf_counter()  # ⬅️ MULAI DARI GENERATE KEY

    key = derive_key_from_password(password)
    plaintext_bytes = plaintext.encode("utf-8")

    padded = pad(plaintext_bytes, AES.block_size)
    iv_bytes = get_random_bytes(16)

    cipher = AES.new(key, AES.MODE_CBC, iv=iv_bytes)
    ciphertext_bytes = cipher.encrypt(padded)

    t_end = time.perf_counter()  # ⬅️ SAMPAI SELESAI ENKRIPSI

    return ciphertext_bytes.hex(), iv_bytes.hex(), t_end - t_start


# =========================
# DEKRIPSI AES (FIXED)
# =========================
def aes_decrypt_cbc(ciphertext_hex: str, iv_hex: str, password: str):
    """
    Dekripsi AES-128 CBC + PKCS7
    Output: plaintext, elapsed_time
    """

    t_start = time.perf_counter()  # ⬅️ MULAI DARI GENERATE KEY

    key = derive_key_from_password(password)
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)
    iv_bytes = bytes.fromhex(iv_hex)

    cipher = AES.new(key, AES.MODE_CBC, iv=iv_bytes)
    padded_plaintext = cipher.decrypt(ciphertext_bytes)

    plaintext_bytes = unpad(padded_plaintext, AES.block_size)
    plaintext = plaintext_bytes.decode("utf-8")

    t_end = time.perf_counter()  # ⬅️ SAMPAI SELESAI DEKRIPSI

    return plaintext, t_end - t_start


# =========================
# STREAMLIT APP
# =========================
st.set_page_config(
    page_title="AES Tunggal - Enkripsi, Dekripsi & Uji Waktu",
    layout="centered"
)

st.title("AES Tunggal (AES-128 CBC) - Enkripsi, Dekripsi & Pengujian Waktu N Kali")

st.write("""
Aplikasi ini melakukan:
1. Enkripsi pesan teks dengan AES-128 CBC berbasis password  
2. Dekripsi ciphertext dengan password yang sama  
3. Pengujian waktu N kali (enkripsi & dekripsi)  
""")

tab_enc, tab_dec = st.tabs(["Enkripsi & Pengujian", "Dekripsi & Pengujian"])

# =========================
# TAB ENKRIPSI
# =========================
with tab_enc:
    st.subheader("Enkripsi AES Tunggal + Uji Waktu")

    plaintext = st.text_area("Masukkan Plaintext")
    password_enc = st.text_input("Masukkan Password", type="password")
    N_enc = st.number_input("Jumlah pengujian (N)", min_value=1, max_value=100, value=5)

    if st.button("Enkripsi & Uji"):
        if not plaintext:
            st.error("Plaintext tidak boleh kosong.")
        elif not password_enc:
            st.error("Password tidak boleh kosong.")
        else:
            hasil = []
            ciphertext_hex_final = ""
            iv_hex_final = ""

            for i in range(N_enc):
                c_hex, iv_hex, t = aes_encrypt_cbc(plaintext, password_enc)

                if i == 0:
                    ciphertext_hex_final = c_hex
                    iv_hex_final = iv_hex

                hasil.append({
                    "Pengujian": i + 1,
                    "Waktu (detik)": t
                })

            df = pd.DataFrame(hasil)
            rata2 = df["Waktu (detik)"].mean()

            st.success("Enkripsi selesai")
            st.write("Ciphertext (hex):")
            st.code(ciphertext_hex_final)

            st.write("IV (hex):")
            st.code(iv_hex_final)

            st.dataframe(df)
            st.info(f"Rata-rata waktu: {rata2:.6f} detik")


# =========================
# TAB DEKRIPSI
# =========================
with tab_dec:
    st.subheader("Dekripsi AES Tunggal + Uji Waktu")

    ciphertext_input = st.text_area("Masukkan Ciphertext (hex)")
    iv_input = st.text_input("Masukkan IV (hex)")
    password_dec = st.text_input("Masukkan Password", type="password")
    N_dec = st.number_input("Jumlah pengujian (N)", min_value=1, max_value=100, value=5)

    if st.button("Dekripsi & Uji"):
        if not ciphertext_input or not iv_input or not password_dec:
            st.error("Semua input harus diisi.")
        else:
            hasil = []
            plaintext_final = ""

            for i in range(N_dec):
                p, t = aes_decrypt_cbc(ciphertext_input, iv_input, password_dec)

                if i == 0:
                    plaintext_final = p

                hasil.append({
                    "Pengujian": i + 1,
                    "Waktu (detik)": t
                })

            df = pd.DataFrame(hasil)
            rata2 = df["Waktu (detik)"].mean()

            st.success("Dekripsi selesai")
            st.write("Plaintext:")
            st.code(plaintext_final)

            st.dataframe(df)
            st.info(f"Rata-rata waktu: {rata2:.6f} detik")
