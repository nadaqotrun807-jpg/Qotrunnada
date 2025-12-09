import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import time
import pandas as pd

# =========================
# Fungsi utilitas
# =========================

def generate_rsa_keypair(bits: int = 2048):
    key = RSA.generate(bits)
    private_key_pem = key.export_key().decode("utf-8")
    public_key_pem = key.publickey().export_key().decode("utf-8")
    return private_key_pem, public_key_pem


def rsa_encrypt_oaep(plaintext: str, public_key_pem: str):
    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    plaintext_bytes = plaintext.encode("utf-8")

    t_start = time.perf_counter()
    ciphertext_bytes = cipher.encrypt(plaintext_bytes)
    t_end = time.perf_counter()

    return ciphertext_bytes.hex(), (t_end - t_start)


def rsa_decrypt_oaep(ciphertext_hex: str, private_key_pem: str):
    private_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)

    t_start = time.perf_counter()
    plaintext_bytes = cipher.decrypt(ciphertext_bytes)
    t_end = time.perf_counter()

    return plaintext_bytes.decode("utf-8"), (t_end - t_start)


# =========================
# Streamlit App
# =========================
st.set_page_config(page_title="RSA Tunggal")

st.title("🔐 RSA Tunggal – Enkripsi, Dekripsi & Pengujian Waktu N Kali")

st.write(
    """
    Kunci publik dan kunci privat dibangkitkan **otomatis** saat aplikasi dijalankan.
    
    Tambahan: fitur **jumlah pengujian (N kali)** untuk mengukur performa waktu RSA.
    """
)

# =========================
# Generate keys otomatis
# =========================
if "private_key_pem" not in st.session_state:
    priv, pub = generate_rsa_keypair()
    st.session_state.private_key_pem = priv
    st.session_state.public_key_pem = pub

# Display keys
st.subheader("🔑 Kunci Publik & Privat RSA")

col1, col2 = st.columns(2)

with col1:
    st.markdown("**Kunci Publik:**")
    st.code(st.session_state.public_key_pem)

with col2:
    st.markdown("**Kunci Privat:**")
    st.code(st.session_state.private_key_pem)

st.divider()

# =========================
# Enkripsi
# =========================
st.subheader("🔒 Enkripsi RSA")

plaintext = st.text_area("Masukkan plaintext:", "Contoh pesan teks.")

# Jumlah pengujian
N = st.number_input(
    "Masukkan jumlah pengujian (N):",
    min_value=1,
    max_value=100,
    value=5,
    step=1
)

if st.button("Enkripsi"):
    hasil = []
    ciphertext_hex, _ = rsa_encrypt_oaep(plaintext, st.session_state.public_key_pem)

    for i in range(N):
        _, waktu = rsa_encrypt_oaep(plaintext, st.session_state.public_key_pem)
        hasil.append({"Pengujian Ke-": i+1, "Waktu Enkripsi (detik)": waktu})

    df_hasil = pd.DataFrame(hasil)
    rata2_time = df_hasil["Waktu Enkripsi (detik)"].mean()

    st.success("Enkripsi selesai.")

    st.markdown("**Ciphertext (hex):**")
    st.code(ciphertext_hex)

    st.markdown("### 📊 Tabel Hasil Pengujian Enkripsi")
    st.dataframe(df_hasil, use_container_width=True)

    st.info(f"⏱ Rata-rata waktu enkripsi: `{rata2_time:.6f}` detik")

st.divider()

# =========================
# Dekripsi
# =========================
st.subheader("🔓 Dekripsi RSA")

cipher_input = st.text_area("Masukkan ciphertext (hex):")

N_dec = st.number_input(
    "Jumlah pengujian dekripsi (N):",
    min_value=1,
    max_value=100,
    value=5,
    step=1,
    key="dec_n"
)

if st.button("Dekripsi"):
    try:
        plaintext_out, _ = rsa_decrypt_oaep(cipher_input, st.session_state.private_key_pem)
        st.success("Dekripsi berhasil!")
        st.markdown("**Hasil plaintext:**")
        st.code(plaintext_out)

        # Lakukan N kali uji waktu dekripsi
        hasil_dec = []
        for i in range(N_dec):
            _, waktu_dec = rsa_decrypt_oaep(cipher_input, st.session_state.private_key_pem)
            hasil_dec.append({"Pengujian Ke-": i+1, "Waktu Dekripsi (detik)": waktu_dec})

        df_dec = pd.DataFrame(hasil_dec)
        rata2_dec = df_dec["Waktu Dekripsi (detik)"].mean()

        st.markdown("### 📊 Tabel Hasil Pengujian Dekripsi")
        st.dataframe(df_dec, use_container_width=True)

        st.info(f"⏱ Rata-rata waktu dekripsi: `{rata2_dec:.6f}` detik")

    except Exception as e:
        st.error(f"Dekripsi gagal: {e}")
