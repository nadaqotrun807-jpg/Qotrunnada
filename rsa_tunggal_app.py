import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import time

# =========================
# Fungsi utilitas
# =========================

def generate_rsa_keypair(bits: int = 2048):
    """
    Membangkitan sepasang kunci RSA (privat & publik) dalam format PEM.
    bits: panjang modulus (default 2048 bit).
    """
    key = RSA.generate(bits)
    private_key_pem = key.export_key().decode("utf-8")
    public_key_pem = key.publickey().export_key().decode("utf-8")
    return private_key_pem, public_key_pem


def rsa_encrypt_oaep(plaintext: str, public_key_pem: str):
    """
    Enkripsi RSA-OAEP (PKCS1_OAEP + SHA-256).
    Output: ciphertext_hex, waktu_enkripsi (detik)
    """
    if not plaintext:
        raise ValueError("Plaintext tidak boleh kosong.")
    if not public_key_pem:
        raise ValueError("Kunci publik tidak boleh kosong.")

    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)

    plaintext_bytes = plaintext.encode("utf-8")

    t_start = time.perf_counter()
    ciphertext_bytes = cipher.encrypt(plaintext_bytes)
    t_end = time.perf_counter()

    ciphertext_hex = ciphertext_bytes.hex()
    elapsed_time = t_end - t_start

    return ciphertext_hex, elapsed_time


def rsa_decrypt_oaep(ciphertext_hex: str, private_key_pem: str):
    """
    Dekripsi RSA-OAEP.
    Output: plaintext (string), waktu_dekripsi (detik)
    """
    if not ciphertext_hex:
        raise ValueError("Ciphertext tidak boleh kosong.")
    if not private_key_pem:
        raise ValueError("Kunci privat tidak boleh kosong.")

    private_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)

    ciphertext_bytes = bytes.fromhex(ciphertext_hex)

    t_start = time.perf_counter()
    plaintext_bytes = cipher.decrypt(ciphertext_bytes)
    t_end = time.perf_counter()

    plaintext = plaintext_bytes.decode("utf-8")
    elapsed_time = t_end - t_start

    return plaintext, elapsed_time


# =========================
# Aplikasi Streamlit
# =========================

st.set_page_config(
    page_title="RSA Tunggal - Kunci, Enkripsi, Dekripsi",
    layout="centered"
)

st.title("🔐 RSA Tunggal (RSA-OAEP) - Pembangkitan Kunci, Enkripsi, dan Dekripsi")

st.write(
    """
    Aplikasi ini melakukan:
    1. **Pembangkitan sepasang kunci RSA 2048-bit** (kunci publik & kunci privat),
    2. **Enkripsi** pesan teks dengan kunci publik (RSA-OAEP + SHA-256),
    3. **Dekripsi** ciphertext dengan kunci privat.

    Waktu enkripsi dan dekripsi diukur menggunakan `time.perf_counter()` dalam satuan detik.
    """
)

# Inisialisasi state kunci
if "private_key_pem" not in st.session_state:
    st.session_state.private_key_pem = ""
if "public_key_pem" not in st.session_state:
    st.session_state.public_key_pem = ""

# =========================
# 1. Pembangkitan Kunci
# =========================
st.header("1. Pembangkitan Kunci RSA 2048-bit")

if st.button("🔑 Bangkitkan Sepasang Kunci RSA 2048-bit", type="primary"):
    priv_pem, pub_pem = generate_rsa_keypair(bits=2048)
    st.session_state.private_key_pem = priv_pem
    st.session_state.public_key_pem = pub_pem
    st.success("Kunci RSA 2048-bit berhasil dibangkitkan.")

col1, col2 = st.columns(2)

with col1:
    st.subheader("Kunci Publik (PEM)")
    st.text_area(
        "Public Key",
        value=st.session_state.public_key_pem,
        height=230,
        key="pub_key_area",
    )

with col2:
    st.subheader("Kunci Privat (PEM)")
    st.text_area(
        "Private Key",
        value=st.session_state.private_key_pem,
        height=230,
        key="priv_key_area",
    )

st.caption("📌 Kunci publik boleh dibagikan. Kunci privat harus dijaga kerahasiaannya.")

st.markdown("---")

# =========================
# 2. Enkripsi RSA
# =========================
st.header("2. Enkripsi RSA Tunggal (RSA-OAEP)")

plaintext = st.text_area(
    "Masukkan Plaintext yang akan dienkripsi",
    value="Contoh pesan teks untuk enkripsi RSA.",
    height=120,
)

public_key_input = st.text_area(
    "Gunakan Kunci Publik RSA (PEM)",
    value=st.session_state.public_key_pem,
    height=150,
    help="Secara default diisi kunci publik yang baru dibangkitkan.",
)

if st.button("🔒 Enkripsi dengan Kunci Publik"):
    try:
        ciphertext_hex, t_enc = rsa_encrypt_oaep(plaintext, public_key_input)

        st.success("Enkripsi RSA berhasil.")
        st.markdown("**Ciphertext (hex):**")
        st.code(ciphertext_hex, language="text")

        st.info(f"⏱ Waktu enkripsi: `{t_enc:.6f}` detik")

        st.caption(
            "Simpan ciphertext di atas. Ciphertext ini hanya dapat didekripsi "
            "dengan kunci privat yang berpasangan."
        )
    except Exception as e:
        st.error(f"Terjadi kesalahan saat enkripsi: {e}")

st.markdown("---")

# =========================
# 3. Dekripsi RSA
# =========================
st.header("3. Dekripsi RSA Tunggal (RSA-OAEP)")

ciphertext_hex_input = st.text_area(
    "Masukkan Ciphertext (hex) hasil enkripsi RSA",
    height=120,
)

private_key_input = st.text_area(
    "Gunakan Kunci Privat RSA (PEM)",
    value=st.session_state.private_key_pem,
    height=150,
    help="Secara default diisi kunci privat yang berpasangan dengan kunci publik di atas.",
)

if st.button("🔓 Dekripsi dengan Kunci Privat"):
    try:
        plaintext_out, t_dec = rsa_decrypt_oaep(ciphertext_hex_input.strip(), private_key_input)

        st.success("Dekripsi RSA berhasil.")
        st.markdown("**Plaintext Hasil Dekripsi:**")
        st.code(plaintext_out, language="text")

        st.info(f"⏱ Waktu dekripsi: `{t_dec:.6f}` detik")
    except Exception as e:
        st.error(
            "Dekripsi gagal. Periksa kembali ciphertext, format hex, "
            "dan kecocokan kunci privat.\n\n"
            f"Detail error: {e}"
        )
