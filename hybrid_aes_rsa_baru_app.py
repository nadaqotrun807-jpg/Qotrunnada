import streamlit as st
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import time
import pandas as pd

# =========================
# CONFIG
# =========================
st.set_page_config(
    page_title="Hybrid AES–RSA",
    layout="wide"
)

st.title("Hybrid AES–RSA (AES-128 CBC) + Pengujian Waktu")

# =========================
# PARAMETER
# =========================
N = st.sidebar.number_input("Jumlah Uji (N)", 1, 100, 5)
rsa_bits = st.sidebar.selectbox("RSA Bit", [2048, 3072, 4096])

# =========================
# GENERATE RSA
# =========================
if "rsa_key" not in st.session_state:
    st.session_state.rsa_key = RSA.generate(rsa_bits)

rsa_key = st.session_state.rsa_key

# =========================
# INPUT AES KEY
# =========================
st.subheader("Kunci AES")

if st.button("Generate AES Key"):
    st.session_state.aes_key = get_random_bytes(16).hex()

aes_key_hex = st.text_input("AES Key (hex)", value=st.session_state.get("aes_key", ""))

# =========================
# INPUT PLAINTEXT
# =========================
plaintext = st.text_area("Plaintext", "Contoh pesan hybrid AES RSA")

# =========================
# FUNGSI ENKRIPSI (FULL TIME)
# =========================
def hybrid_encrypt_once(K_AES, P_bytes, rsa_key):
    t_start = time.perf_counter()

    # Padding
    padded = pad(P_bytes, AES.block_size)

    # AES
    iv = get_random_bytes(16)
    cipher_aes = AES.new(K_AES, AES.MODE_CBC, iv=iv)
    C_text = cipher_aes.encrypt(padded)

    # RSA encrypt key
    cipher_rsa = PKCS1_OAEP.new(rsa_key.publickey(), hashAlgo=SHA256)
    C_key = cipher_rsa.encrypt(K_AES)

    t_end = time.perf_counter()
    return C_text, C_key, iv, (t_end - t_start)


# =========================
# FUNGSI DEKRIPSI (FULL TIME)
# =========================
def hybrid_decrypt_once(C_text, C_key, iv, rsa_key):
    t_start = time.perf_counter()

    # RSA decrypt key
    cipher_rsa = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    K_AES = cipher_rsa.decrypt(C_key)

    # AES decrypt
    cipher_aes = AES.new(K_AES, AES.MODE_CBC, iv=iv)
    padded = cipher_aes.decrypt(C_text)

    # Unpad
    P = unpad(padded, AES.block_size)

    t_end = time.perf_counter()
    return K_AES, P, (t_end - t_start)


# =========================
# ENKRIPSI
# =========================
if st.button("ENKRIPSI"):
    if not plaintext or not aes_key_hex:
        st.warning("Isi plaintext & key dulu")
    else:
        K_AES = bytes.fromhex(aes_key_hex)
        P_bytes = plaintext.encode()

        runs = []
        T_enc = []

        for i in range(N):
            C_text, C_key, iv, t = hybrid_encrypt_once(K_AES, P_bytes, rsa_key)

            T_enc.append(t)
            runs.append((C_text, C_key, iv))

        st.session_state.runs = runs
        st.session_state.plaintext = plaintext

        df = pd.DataFrame({
            "Uji": range(1, N+1),
            "T_enc": T_enc
        })

        st.write(df)
        st.success(f"Rata-rata: {sum(T_enc)/len(T_enc):.6f} detik")

        # tampilkan contoh
        last = runs[-1]
        st.code(last[0].hex(), language="text")
        st.code(last[1].hex(), language="text")
        st.code(last[2].hex(), language="text")


# =========================
# DEKRIPSI
# =========================
if st.button("DEKRIPSI"):
    if "runs" not in st.session_state:
        st.warning("Lakukan enkripsi dulu")
    else:
        runs = st.session_state.runs
        P_ref = st.session_state.plaintext.encode()

        T_dec = []
        status = []

        for C_text, C_key, iv in runs:
            K_AES, P, t = hybrid_decrypt_once(C_text, C_key, iv, rsa_key)

            T_dec.append(t)
            status.append("Valid" if P == P_ref else "Tidak Valid")

        df = pd.DataFrame({
            "Uji": range(1, len(runs)+1),
            "T_dec": T_dec,
            "Status": status
        })

        st.write(df)
        st.success(f"Rata-rata: {sum(T_dec)/len(T_dec):.6f} detik")
