# hybrid_aes_rsa_full_process.py
# Jalankan:
# pip install streamlit pycryptodome pandas
# streamlit run hybrid_aes_rsa_full_process.py

import streamlit as st
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import time
import pandas as pd

st.set_page_config(
    page_title="Hybrid AES–RSA Full Process Timing",
    layout="wide"
)

st.title("🔐 Hybrid AES–RSA (FULL PROCESS TIMING)")

st.write("""
Pengukuran waktu mencakup:
- Generate RSA key
- Generate AES key
- Padding
- Generate IV
- AES Encryption
- RSA Encryption
""")

# =========================
# INPUT
# =========================
N = st.number_input("Jumlah pengujian (N)", 1, 50, 5)
rsa_bits = st.selectbox("Panjang RSA (bit)", [2048, 3072, 4096])
plaintext = st.text_area("Plaintext", height=120)

btn_enc = st.button("🔒 Enkripsi Hybrid (Full Process)")
btn_dec = st.button("🔓 Dekripsi Hybrid")

# =========================
# FUNGSI FULL ENKRIPSI
# =========================
def hybrid_encrypt_full(P_bytes, rsa_bits):

    t_start = time.perf_counter()

    # 1. Generate RSA key
    rsa_key = RSA.generate(rsa_bits)

    # 2. Generate AES key
    K_AES = get_random_bytes(16)

    # 3. Padding
    P_padded = pad(P_bytes, AES.block_size)

    # 4. AES Encryption
    iv = get_random_bytes(16)
    cipher_aes = AES.new(K_AES, AES.MODE_CBC, iv=iv)
    C_text = cipher_aes.encrypt(P_padded)

    # 5. RSA Encryption
    cipher_rsa = PKCS1_OAEP.new(rsa_key.publickey(), hashAlgo=SHA256)
    C_key = cipher_rsa.encrypt(K_AES)

    t_end = time.perf_counter()

    return rsa_key, K_AES, C_text, C_key, iv, (t_end - t_start)


# =========================
# FUNGSI DEKRIPSI
# =========================
def hybrid_decrypt(C_text, C_key, iv, rsa_key):

    t_start = time.perf_counter()

    cipher_rsa = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    K_AES = cipher_rsa.decrypt(C_key)

    cipher_aes = AES.new(K_AES, AES.MODE_CBC, iv=iv)
    P_padded = cipher_aes.decrypt(C_text)
    P = unpad(P_padded, AES.block_size)

    t_end = time.perf_counter()

    return P.decode(), (t_end - t_start)


# =========================
# ENKRIPSI
# =========================
if btn_enc:
    if not plaintext:
        st.error("Plaintext kosong")
    else:
        P_bytes = plaintext.encode()

        runs = []
        times = []

        for i in range(N):
            rsa_key, K_AES, C_text, C_key, iv, t = hybrid_encrypt_full(P_bytes, rsa_bits)

            runs.append({
                "rsa_key": rsa_key,
                "C_text": C_text,
                "C_key": C_key,
                "iv": iv
            })

            times.append(t)

        st.session_state.runs = runs

        df = pd.DataFrame({
            "Uji": list(range(1, N+1)),
            "Waktu Enkripsi": times
        })

        st.success("Enkripsi selesai")

        st.dataframe(df)
        st.info(f"Rata-rata: {df['Waktu Enkripsi'].mean():.6f} detik")

        last = runs[-1]
        st.markdown("### Contoh Output (Uji terakhir)")
        st.code(last["C_text"].hex())
        st.code(last["C_key"].hex())
        st.code(last["iv"].hex())


# =========================
# DEKRIPSI
# =========================
if btn_dec:
    runs = st.session_state.get("runs", [])

    if not runs:
        st.error("Belum ada data enkripsi")
    else:
        times = []
        plaintexts = []

        for r in runs:
            P, t = hybrid_decrypt(
                r["C_text"],
                r["C_key"],
                r["iv"],
                r["rsa_key"]
            )

            plaintexts.append(P)
            times.append(t)

        df = pd.DataFrame({
            "Uji": list(range(1, len(runs)+1)),
            "Waktu Dekripsi": times
        })

        st.success("Dekripsi selesai")

        st.dataframe(df)
        st.info(f"Rata-rata: {df['Waktu Dekripsi'].mean():.6f} detik")

        st.markdown("### Plaintext hasil dekripsi")
        st.code(plaintexts[-1])
