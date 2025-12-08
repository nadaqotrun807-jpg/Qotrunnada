import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import time

# =========================
# Fungsi utilitas
# =========================

def derive_key_from_password(password: str) -> bytes:
    """
    Mengubah password (string) menjadi kunci AES 128-bit.
    Di sini digunakan SHA-256 lalu dipotong 16 byte (128 bit).
    """
    if not password:
        raise ValueError("Password tidak boleh kosong.")
    sha256_hash = hashlib.sha256(password.encode("utf-8")).digest()
    return sha256_hash[:16]  # 16 byte = 128 bit


def aes_encrypt_gcm(plaintext: str, password: str):
    """
    Enkripsi AES-128 GCM.
    Input  : plaintext (string), password (string)
    Output : ciphertext_hex, nonce_hex, tag_hex, elapsed_time (detik)
    """
    key = derive_key_from_password(password)
    plaintext_bytes = plaintext.encode("utf-8")

    t_start = time.perf_counter()
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext_bytes, tag_bytes = cipher.encrypt_and_digest(plaintext_bytes)
    t_end = time.perf_counter()

    nonce_bytes = cipher.nonce

    ciphertext_hex = ciphertext_bytes.hex()
    nonce_hex = nonce_bytes.hex()
    tag_hex = tag_bytes.hex()
    elapsed_time = t_end - t_start

    return ciphertext_hex, nonce_hex, tag_hex, elapsed_time


def aes_decrypt_gcm(ciphertext_hex: str, nonce_hex: str, tag_hex: str, password: str):
    """
    Dekripsi AES-128 GCM.
    Input  : ciphertext_hex, nonce_hex, tag_hex, password
    Output : plaintext (string), elapsed_time (detik)
    """
    key = derive_key_from_password(password)

    ciphertext_bytes = bytes.fromhex(ciphertext_hex)
    nonce_bytes = bytes.fromhex(nonce_hex)
    tag_bytes = bytes.fromhex(tag_hex)

    t_start = time.perf_counter()
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce_bytes)
    plaintext_bytes = cipher.decrypt_and_verify(ciphertext_bytes, tag_bytes)
    t_end = time.perf_counter()

    plaintext = plaintext_bytes.decode("utf-8")
    elapsed_time = t_end - t_start

    return plaintext, elapsed_time


# =========================
# Aplikasi Streamlit
# =========================

st.set_page_config(
    page_title="AES Tunggal - Enkripsi & Dekripsi",
    layout="centered"
)

st.title("🔐 AES Tunggal (AES-128 GCM) - Enkripsi & Dekripsi")

st.write(
    """
    Aplikasi ini melakukan **enkripsi** dan **dekripsi** pesan teks menggunakan 
    algoritma **AES-128** dalam mode **Galois/Counter Mode (GCM)**.
    
    - Kunci AES dibentuk dari *password* menggunakan SHA-256 (dipotong 128-bit).
    - Hasil enkripsi berupa: `ciphertext (hex)`, `nonce (hex)`, dan `tag (hex)`.
    - Waktu proses diukur menggunakan `time.perf_counter()` dalam satuan detik.
    """
)

tab_enc, tab_dec = st.tabs(["🔒 Enkripsi", "🔓 Dekripsi"])

# =========================
# Tab ENKRIPSI
# =========================
with tab_enc:
    st.subheader("Enkripsi AES Tunggal (AES-128 GCM)")

    plaintext = st.text_area(
        "Masukkan Plaintext",
        value="Contoh pesan teks yang akan dienkripsi.",
        height=150
    )

    password_enc = st.text_input(
        "Masukkan Password (untuk membentuk kunci AES)",
        type="password",
        help="Password ini akan di-hash menjadi kunci AES 128-bit."
    )

    if st.button("Enkripsi Sekarang", type="primary"):
        if not plaintext:
            st.error("Plaintext tidak boleh kosong.")
        elif not password_enc:
            st.error("Password tidak boleh kosong.")
        else:
            try:
                ciphertext_hex, nonce_hex, tag_hex, t_enc = aes_encrypt_gcm(
                    plaintext, password_enc
                )

                st.success("Enkripsi berhasil!")

                st.markdown("**Ciphertext (hex):**")
                st.code(ciphertext_hex, language="text")

                st.markdown("**Nonce (hex):**")
                st.code(nonce_hex, language="text")

                st.markdown("**Tag (hex):**")
                st.code(tag_hex, language="text")

                st.info(f"⏱ Waktu enkripsi: `{t_enc:.6f}` detik")

                st.caption(
                    "Simpan ciphertext, nonce, dan tag di atas. "
                    "Nilai tersebut dibutuhkan kembali pada proses dekripsi."
                )

            except Exception as e:
                st.error(f"Terjadi kesalahan saat enkripsi: {e}")

# =========================
# Tab DEKRIPSI
# =========================
with tab_dec:
    st.subheader("Dekripsi AES Tunggal (AES-128 GCM)")

    ciphertext_hex_input = st.text_area(
        "Masukkan Ciphertext (hex)",
        height=120
    )

    nonce_hex_input = st.text_input(
        "Masukkan Nonce (hex)",
        help="Nonce yang dihasilkan saat enkripsi."
    )

    tag_hex_input = st.text_input(
        "Masukkan Tag (hex)",
        help="Tag autentikasi yang dihasilkan saat enkripsi."
    )

    password_dec = st.text_input(
        "Masukkan Password (sama dengan saat enkripsi)",
        type="password"
    )

    if st.button("Dekripsi Sekarang"):
        if not ciphertext_hex_input or not nonce_hex_input or not tag_hex_input:
            st.error("Ciphertext, nonce, dan tag wajib diisi.")
        elif not password_dec:
            st.error("Password tidak boleh kosong.")
        else:
            try:
                plaintext_out, t_dec = aes_decrypt_gcm(
                    ciphertext_hex_input.strip(),
                    nonce_hex_input.strip(),
                    tag_hex_input.strip(),
                    password_dec
                )

                st.success("Dekripsi berhasil!")

                st.markdown("**Plaintext Hasil Dekripsi:**")
                st.code(plaintext_out, language="text")

                st.info(f"⏱ Waktu dekripsi: `{t_dec:.6f}` detik")

            except ValueError:
                st.error(
                    "Dekripsi gagal: kemungkinan password salah, "
                    "nonce/tag tidak sesuai, atau data sudah berubah (MAC check failed)."
                )
            except Exception as e:
                st.error(f"Terjadi kesalahan saat dekripsi: {e}")
