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

st.set_page_config(page_title="RSA Tunggal – Tampil n, e, d, p, q")

st.title("🔐 RSA Tunggal – Enkripsi, Dekripsi & Parameter Kunci (n, e, d, p, q)")

st.write(
    """
    Aplikasi ini menampilkan **struktur matematika kunci RSA lengkap**, serta
    fitur enkripsi, dekripsi, dan pengujian waktu N kali.
    """
)

# =========================
# Generate keys otomatis
# =========================
if "private_key_pem" not in st.session_state:
    priv, pub = generate_rsa_keypair()
    st.session_state.private_key_pem = priv
    st.session_state.public_key_pem = pub

# Import RSA objects
rsa_priv = RSA.import_key(st.session_state.private_key_pem)
rsa_pub = RSA.import_key(st.session_state.public_key_pem)

# =========================
# Ambil parameter matematis
# =========================

n = rsa_pub.n
e = rsa_pub.e
d = rsa_priv.d
p = rsa_priv.p
q = rsa_priv.q

# =========================
# Tampilkan parameter RSA
# =========================

st.subheader("🔑 Parameter Kunci Publik dan Privat RSA")

st.markdown("### 🔵 Kunci Publik (n & e)")
st.markdown("**Modulus (n) – decimal:**")
st.code(str(n))

st.markdown("**Modulus (n) – hexadecimal:**")
st.code(hex(n))

st.markdown("**Eksponen Publik (e):**")
st.code(str(e))


st.markdown("### 🔴 Kunci Privat (d, p, q)")
st.markdown("**Eksponen Privat (d):**")
st.code(str(d))

st.markdown("**Bilangan Prima p – decimal:**")
st.code(str(p))

st.markdown("**Bilangan Prima q – decimal:**")
st.code(str(q))

st.markdown("**Bilangan Prima p – hex:**")
st.code(hex(p))

st.markdown("**Bilangan Prima q – hex:**")
st.code(hex(q))

st.divider()


# =========================
# Enkripsi
# =========================

st.subheader("🔒 Enkripsi RSA")

plaintext = st.text_area("Masukkan plaintext:", "Contoh pesan teks.")

N = st.number_input(
    "Masukkan jumlah pengujian (N):",
    min_value=1, max_value=100, value=5, step=1
)

if st.button("Enkripsi"):
    hasil = []
    ciphertext_hex, _ = rsa_encrypt_oaep(plaintext, st.session_state.public_key_pem)

    for i in range(N):
        _, waktu = rsa_encrypt_oaep(plaintext, st.session_state.public_key_pem)
        hasil.append({"Pengujian Ke-": i + 1, "Waktu Enkripsi (detik)": waktu})

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
    min_value=1, max_value=100, value=5, step=1,
    key="dec_n"
)

if st.button("Dekripsi"):
    try:
        plaintext_out, _ = rsa_decrypt_oaep(cipher_input, st.session_state.private_key_pem)
        st.success("Dekripsi berhasil!")
        st.code(plaintext_out)

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
