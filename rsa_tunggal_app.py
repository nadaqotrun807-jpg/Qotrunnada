import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import time

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

st.title("🔐 RSA Tunggal – Enkripsi & Dekripsi dengan Kunci Otomatis")

st.write(
    """
    Kunci publik dan kunci privat **langsung dibangkitkan otomatis** ketika aplikasi dijalankan.
    Kamu tidak perlu mengisi atau membuatnya sendiri.
    """
)

# =========================
# Generate keys otomatis
# =========================
if "private_key_pem" not in st.session_state:
    priv, pub = generate_rsa_keypair()
    st.session_state.private_key_pem = priv
    st.session_state.public_key_pem = pub

# Tampilkan kunci
st.subheader("🔑 Kunci Publik & Privat RSA (Otomatis Terbentuk)")

col1, col2 = st.columns(2)

with col1:
    st.markdown("**Kunci Publik (PEM):**")
    st.code(st.session_state.public_key_pem, language="text")

with col2:
    st.markdown("**Kunci Privat (PEM):**")
    st.code(st.session_state.private_key_pem, language="text")

st.divider()

# =========================
# Enkripsi
# =========================
st.subheader("🔒 Enkripsi RSA")

plaintext = st.text_area("Masukkan plaintext:", "Contoh pesan teks.")

if st.button("Enkripsi"):
    ciphertext_hex, t_enc = rsa_encrypt_oaep(plaintext, st.session_state.public_key_pem)

    st.success("Enkripsi berhasil!")
    st.markdown("**Ciphertext (hex):**")
    st.code(ciphertext_hex)

    st.info(f"⏱ Waktu enkripsi: {t_enc:.6f} detik")

st.divider()

# =========================
# Dekripsi
# =========================
st.subheader("🔓 Dekripsi RSA")

cipher_input = st.text_area("Masukkan ciphertext (hex):")

if st.button("Dekripsi"):
    try:
        plaintext_out, t_dec = rsa_decrypt_oaep(cipher_input, st.session_state.private_key_pem)

        st.success("Dekripsi berhasil!")
        st.markdown("**Hasil plaintext:**")
        st.code(plaintext_out)

        st.info(f"⏱ Waktu dekripsi: {t_dec:.6f} detik")

    except Exception as e:
        st.error(f"Dekripsi gagal: {e}")
