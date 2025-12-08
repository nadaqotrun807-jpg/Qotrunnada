import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import time

# =========================
# Fungsi utilitas RSA
# =========================

def generate_rsa_keypair(bits: int = 2048):
    """
    Membangkitan sepasang kunci RSA (privat & publik) dalam format PEM.
    bits: panjang modulus (1024 / 2048 / 3072, dst).
    """
    key = RSA.generate(bits)
    private_key_pem = key.export_key().decode("utf-8")
    public_key_pem = key.publickey().export_key().decode("utf-8")
    return private_key_pem, public_key_pem


def rsa_encrypt_oaep(plaintext: str, public_key_pem: str):
    """
    Enkripsi RSA-OAEP.
    Input  : plaintext (string), public_key_pem (PEM string)
    Output : ciphertext_hex, elapsed_time (detik)
    """
    if not plaintext:
        raise ValueError("Plaintext tidak boleh kosong.")
    if not public_key_pem:
        raise ValueError("Kunci publik tidak boleh kosong.")

    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)

    # Catatan: RSA hanya bisa mengenkripsi pesan dengan panjang terbatas
    # tergantung ukuran kunci & padding OAEP.
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
    Input  : ciphertext_hex (hex string), private_key_pem (PEM string)
    Output : plaintext (string), elapsed_time (detik)
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
    page_title="RSA Tunggal - Enkripsi & Dekripsi",
    layout="centered"
)

st.title("🔐 RSA Tunggal (RSA-OAEP) - Enkripsi & Dekripsi")

st.write(
    """
    Aplikasi ini melakukan **enkripsi** dan **dekripsi** pesan teks menggunakan 
    algoritma **RSA** dengan skema **RSA-OAEP (PKCS1_OAEP + SHA-256)**.
    
    - Kunci RSA dibangkitkan secara acak dengan panjang modulus tertentu (1024 / 2048 / 3072 bit).
    - Proses enkripsi menghasilkan ciphertext dalam bentuk **hex**.
    - Waktu enkripsi dan dekripsi diukur menggunakan `time.perf_counter()` dalam satuan detik.
    
    > Catatan: RSA hanya dapat mengenkripsi pesan dengan panjang yang terbatas 
    > (bergantung pada panjang kunci dan padding OAEP). Untuk data besar, 
    > biasanya RSA dipakai hanya untuk mengenkripsi kunci simetris (misalnya kunci AES).
    """
)

tab_key, tab_enc, tab_dec = st.tabs(
    ["🔑 Pembangkitan Kunci RSA", "🔒 Enkripsi RSA Tunggal", "🔓 Dekripsi RSA Tunggal"]
)

# =========================
# Tab 1: Pembangkitan Kunci
# =========================
with tab_key:
    st.subheader("Pembangkitan Sepasang Kunci RSA")

    bits = st.selectbox(
        "Pilih Panjang Kunci (modulus)",
        options=[1024, 2048, 3072],
        index=1,
        help="Semakin besar nilai bit, semakin kuat keamanan namun waktu komputasi lebih lama."
    )

    if "private_key_pem" not in st.session_state:
        st.session_state.private_key_pem = ""
    if "public_key_pem" not in st.session_state:
        st.session_state.public_key_pem = ""

    if st.button("Bangkitkan Kunci RSA", type="primary"):
        priv_pem, pub_pem = generate_rsa_keypair(bits)
        st.session_state.private_key_pem = priv_pem
        st.session_state.public_key_pem = pub_pem

        st.success(f"Kunci RSA {bits}-bit berhasil dibangkitkan.")

    st.markdown("**Kunci Privat (PEM):**")
    st.text_area(
        "Private Key",
        value=st.session_state.private_key_pem,
        height=200,
        key="priv_key_area"
    )

    st.markdown("**Kunci Publik (PEM):**")
    st.text_area(
        "Public Key",
        value=st.session_state.public_key_pem,
        height=200,
        key="pub_key_area"
    )

    st.caption(
        "Simpan kunci privat dengan aman. Kunci publik boleh dibagikan kepada pihak lain "
        "untuk keperluan enkripsi."
    )

# =========================
# Tab 2: Enkripsi
# =========================
with tab_enc:
    st.subheader("Enkripsi RSA Tunggal (RSA-OAEP)")

    plaintext = st.text_area(
        "Masukkan Plaintext",
        value="Contoh pesan teks yang akan dienkripsi dengan RSA.",
        height=150
    )

    public_key_input = st.text_area(
        "Masukkan Kunci Publik RSA (PEM)",
        value=st.session_state.public_key_pem,
        height=200,
        help="Gunakan kunci publik hasil pembangkitan di tab sebelumnya, atau paste kunci publik lain."
    )

    if st.button("Enkripsi dengan RSA", key="btn_encrypt_rsa", type="primary"):
        try:
            ciphertext_hex, t_enc = rsa_encrypt_oaep(plaintext, public_key_input)

            st.success("Enkripsi RSA berhasil!")

            st.markdown("**Ciphertext (hex):**")
            st.code(ciphertext_hex, language="text")

            st.info(f"⏱ Waktu enkripsi RSA: `{t_enc:.6f}` detik")

            st.caption(
                "Simpan ciphertext di atas. Ciphertext tersebut hanya dapat didekripsi "
                "menggunakan kunci privat RSA yang sesuai."
            )

        except ValueError as ve:
            st.error(f"Input tidak valid: {ve}")
        except Exception as e:
            st.error(f"Terjadi kesalahan saat enkripsi: {e}")

# =========================
# Tab 3: Dekripsi
# =========================
with tab_dec:
    st.subheader("Dekripsi RSA Tunggal (RSA-OAEP)")

    ciphertext_hex_input = st.text_area(
        "Masukkan Ciphertext (hex)",
        height=150,
        help="Paste ciphertext hex hasil enkripsi RSA."
    )

    private_key_input = st.text_area(
        "Masukkan Kunci Privat RSA (PEM)",
        value=st.session_state.private_key_pem,
        height=200,
        help="Gunakan kunci privat yang berpasangan dengan kunci publik saat enkripsi."
    )

    if st.button("Dekripsi dengan RSA", key="btn_decrypt_rsa"):
        try:
            plaintext_out, t_dec = rsa_decrypt_oaep(ciphertext_hex_input.strip(), private_key_input)

            st.success("Dekripsi RSA berhasil!")

            st.markdown("**Plaintext Hasil Dekripsi:**")
            st.code(plaintext_out, language="text")

            st.info(f"⏱ Waktu dekripsi RSA: `{t_dec:.6f}` detik")

        except ValueError as ve:
            st.error(f"Input tidak valid: {ve}")
        except Exception as e:
            st.error(
                "Terjadi kesalahan saat dekripsi: "
                f"{e}\n\nPastikan ciphertext, format hex, dan kunci privat sudah benar serta berpasangan."
            )
