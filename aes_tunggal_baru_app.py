import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import time
import pandas as pd

# =========================
# Fungsi Utilitas AES
# =========================

def derive_key_from_password(password: str) -> bytes:
    if not password:
        raise ValueError("Password tidak boleh kosong.")
    sha256_hash = hashlib.sha256(password.encode("utf-8")).digest()
    return sha256_hash[:16]  # 128-bit


def aes_encrypt_cbc(plaintext: str, password: str):
    """
    Enkripsi AES-128 CBC
    Waktu mencakup:
    - derive key
    - padding
    - generate IV
    - enkripsi
    """
    t_start = time.perf_counter()

    key = derive_key_from_password(password)
    plaintext_bytes = plaintext.encode("utf-8")
    padded = pad(plaintext_bytes, AES.block_size)
    iv_bytes = get_random_bytes(16)

    cipher = AES.new(key, AES.MODE_CBC, iv=iv_bytes)
    ciphertext_bytes = cipher.encrypt(padded)

    t_end = time.perf_counter()

    return ciphertext_bytes.hex(), iv_bytes.hex(), (t_end - t_start)


def aes_decrypt_cbc(ciphertext_hex: str, iv_hex: str, password: str):
    """
    Dekripsi AES-128 CBC
    Waktu mencakup:
    - derive key
    - dekripsi
    - unpadding
    """
    t_start = time.perf_counter()

    key = derive_key_from_password(password)
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)
    iv_bytes = bytes.fromhex(iv_hex)

    cipher = AES.new(key, AES.MODE_CBC, iv=iv_bytes)
    padded_plaintext = cipher.decrypt(ciphertext_bytes)
    plaintext_bytes = unpad(padded_plaintext, AES.block_size)

    t_end = time.perf_counter()

    return plaintext_bytes.decode("utf-8"), (t_end - t_start)


# =========================
# Streamlit UI
# =========================

st.set_page_config(
    page_title="AES Tunggal - Full Process Timing",
    layout="centered"
)

st.title("🔐 AES-128 CBC (Full Process Timing)")

st.write("""
Aplikasi ini mengukur waktu komputasi AES secara **menyeluruh**, meliputi:
- Pembangkitan kunci (SHA-256)
- Padding
- Generate IV
- Enkripsi dan Dekripsi
""")

tab1, tab2 = st.tabs(["🔒 Enkripsi", "🔓 Dekripsi"])

# =========================
# ENKRIPSI
# =========================
with tab1:
    plaintext = st.text_area("Plaintext", height=130)
    password = st.text_input("Password", type="password")
    N = st.number_input("Jumlah pengujian (N)", 1, 100, 5)

    if st.button("Enkripsi & Uji"):
        if not plaintext or not password:
            st.error("Input tidak boleh kosong")
        else:
            hasil = []
            c_final, iv_final = "", ""

            for i in range(N):
                c, iv, t = aes_encrypt_cbc(plaintext, password)

                if i == 0:
                    c_final = c
                    iv_final = iv

                hasil.append({
                    "Pengujian": i+1,
                    "Waktu (detik)": t
                })

            df = pd.DataFrame(hasil)

            st.success("Selesai")

            st.markdown("**Ciphertext:**")
            st.code(c_final)

            st.markdown("**IV:**")
            st.code(iv_final)

            st.dataframe(df)
            st.info(f"Rata-rata: {df['Waktu (detik)'].mean():.6f} detik")


# =========================
# DEKRIPSI
# =========================
with tab2:
    ciphertext = st.text_area("Ciphertext (hex)", height=120)
    iv = st.text_input("IV (hex)")
    password = st.text_input("Password", type="password", key="dec_pass")
    N = st.number_input("Jumlah pengujian (N)", 1, 100, 5, key="dec_n")

    if st.button("Dekripsi & Uji"):
        if not ciphertext or not iv or not password:
            st.error("Semua field wajib diisi")
        else:
            try:
                hasil = []

                # tampilkan plaintext sekali
                plaintext, _ = aes_decrypt_cbc(ciphertext.strip(), iv.strip(), password)
                st.success("Dekripsi berhasil")
                st.code(plaintext)

                for i in range(N):
                    _, t = aes_decrypt_cbc(ciphertext.strip(), iv.strip(), password)
                    hasil.append({
                        "Pengujian": i+1,
                        "Waktu (detik)": t
                    })

                df = pd.DataFrame(hasil)

                st.dataframe(df)
                st.info(f"Rata-rata: {df['Waktu (detik)'].mean():.6f} detik")

            except:
                st.error("Dekripsi gagal (password/IV/ciphertext salah)")
