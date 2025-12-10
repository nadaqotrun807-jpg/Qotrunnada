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
    """
    Mengubah password (string) menjadi kunci AES 128-bit.
    Di sini digunakan SHA-256 lalu dipotong 16 byte (128 bit).
    """
    if not password:
        raise ValueError("Password tidak boleh kosong.")
    sha256_hash = hashlib.sha256(password.encode("utf-8")).digest()
    return sha256_hash[:16]  # 16 byte = 128 bit


def aes_encrypt_cbc(plaintext: str, password: str):
    """
    Enkripsi AES-128 CBC + PKCS7 padding.
    Output: ciphertext_hex, iv_hex, elapsed_time (detik)
    """
    key = derive_key_from_password(password)
    plaintext_bytes = plaintext.encode("utf-8")

    # PKCS7 padding agar panjang kelipatan 16 byte
    padded = pad(plaintext_bytes, AES.block_size)

    iv_bytes = get_random_bytes(16)

    t_start = time.perf_counter()
    cipher = AES.new(key, AES.MODE_CBC, iv=iv_bytes)
    ciphertext_bytes = cipher.encrypt(padded)
    t_end = time.perf_counter()

    ciphertext_hex = ciphertext_bytes.hex()
    iv_hex = iv_bytes.hex()
    elapsed_time = t_end - t_start

    return ciphertext_hex, iv_hex, elapsed_time


def aes_decrypt_cbc(ciphertext_hex: str, iv_hex: str, password: str):
    """
    Dekripsi AES-128 CBC + PKCS7 unpadding.
    Output: plaintext (string), elapsed_time (detik)
    """
    key = derive_key_from_password(password)

    ciphertext_bytes = bytes.fromhex(ciphertext_hex)
    iv_bytes = bytes.fromhex(iv_hex)

    t_start = time.perf_counter()
    cipher = AES.new(key, AES.MODE_CBC, iv=iv_bytes)
    padded_plaintext = cipher.decrypt(ciphertext_bytes)
    plaintext_bytes = unpad(padded_plaintext, AES.block_size)
    t_end = time.perf_counter()

    plaintext = plaintext_bytes.decode("utf-8")
    elapsed_time = t_end - t_start

    return plaintext, elapsed_time


# =========================
# Aplikasi Streamlit
# =========================

st.set_page_config(
    page_title="AES Tunggal - Enkripsi, Dekripsi & Pengujian Waktu",
    layout="centered"
)

st.title("🔐 AES Tunggal (AES-128 CBC) – Enkripsi, Dekripsi & Pengujian Waktu N Kali")

st.write(
    """
    Aplikasi ini melakukan:
    1. **Enkripsi** pesan teks dengan AES-128 CBC berbasis password,
    2. **Dekripsi** ciphertext dengan password yang sama,
    3. **Pengujian waktu N kali** untuk enkripsi dan dekripsi (tabel + rata-rata).

    Mode CBC menggunakan IV (Initialization Vector) 16 byte dan padding PKCS7,
    sehingga panjang ciphertext selalu kelipatan 16 byte.
    """
)

tab_enc, tab_dec = st.tabs(["🔒 Enkripsi & Pengujian", "🔓 Dekripsi & Pengujian"])

# =========================
# TAB 1: ENKRIPSI + PENGUJIAN
# =========================
with tab_enc:
    st.subheader("Enkripsi AES Tunggal (AES-128 CBC) + Pengujian N Kali")

    plaintext = st.text_area(
        "Masukkan Plaintext",
        value="Contoh pesan teks yang akan dienkripsi dengan AES-CBC.",
        height=140
    )

    password_enc = st.text_input(
        "Masukkan Password (untuk membentuk kunci AES)",
        type="password",
        help="Password akan di-hash dengan SHA-256, lalu diambil 128-bit pertama sebagai kunci AES."
    )

    N_enc = st.number_input(
        "Jumlah pengujian enkripsi (N):",
        min_value=1,
        max_value=100,
        value=5,
        step=1
    )

    if st.button("🔒 Enkripsi & Uji N Kali"):
        if not plaintext:
            st.error("Plaintext tidak boleh kosong.")
        elif not password_enc:
            st.error("Password tidak boleh kosong.")
        else:
            try:
                hasil_enc = []
                ciphertext_hex_final = ""
                iv_hex_final = ""

                # Lakukan enkripsi N kali, simpan waktu tiap uji
                for i in range(N_enc):
                    c_hex, iv_hex, t_enc = aes_encrypt_cbc(plaintext, password_enc)

                    # Simpan hasil enkripsi dari uji pertama (atau terakhir) untuk ditampilkan
                    if i == 0:
                        ciphertext_hex_final = c_hex
                        iv_hex_final = iv_hex

                    hasil_enc.append({
                        "Pengujian Ke-": i + 1,
                        "Waktu Enkripsi (detik)": t_enc
                    })

                df_enc = pd.DataFrame(hasil_enc)
                rata2_enc = df_enc["Waktu Enkripsi (detik)"].mean()

                st.success("Enkripsi dan pengujian selesai.")

                st.markdown("**Ciphertext (hex) – diambil dari pengujian pertama:**")
                st.code(ciphertext_hex_final, language="text")

                st.markdown("**IV (Initialization Vector) (hex):**")
                st.code(iv_hex_final, language="text")

                st.markdown("### 📊 Tabel Hasil Pengujian Enkripsi AES")
                st.dataframe(df_enc, use_container_width=True)

                st.info(f"⏱ Rata-rata waktu enkripsi: `{rata2_enc:.6f}` detik")

                st.caption(
                    "Simpan ciphertext dan IV di atas. Nilai tersebut akan digunakan pada proses dekripsi."
                )

            except Exception as e:
                st.error(f"Terjadi kesalahan saat enkripsi/pengujian: {e}")

# =========================
# TAB 2: DEKRIPSI + PENGUJIAN
# =========================
with tab_dec:
    st.subheader("Dekripsi AES Tunggal (AES-128 CBC) + Pengujian N Kali")

    ciphertext_hex_input = st.text_area(
        "Masukkan Ciphertext (hex)",
        height=120,
        help="Gunakan ciphertext (hex) hasil enkripsi AES-CBC."
    )

    iv_hex_input = st.text_input(
        "Masukkan IV (hex) 16 byte",
        help="IV yang dihasilkan saat enkripsi."
    )

    password_dec = st.text_input(
        "Masukkan Password (sama dengan saat enkripsi)",
        type="password"
    )

    N_dec = st.number_input(
        "Jumlah pengujian dekripsi (N):",
        min_value=1,
        max_value=100,
        value=5,
        step=1,
        key="N_dec_input"
    )

    if st.button("🔓 Dekripsi & Uji N Kali"):
        if not ciphertext_hex_input or not iv_hex_input:
            st.error("Ciphertext dan IV wajib diisi.")
        elif not password_dec:
            st.error("Password tidak boleh kosong.")
        else:
            try:
                # Dekripsi sekali dulu untuk memastikan data valid & tampilkan plaintext
                plaintext_out, t_first = aes_decrypt_cbc(
                    ciphertext_hex_input.strip(),
                    iv_hex_input.strip(),
                    password_dec
                )

                st.success("Dekripsi berhasil.")

                st.markdown("**Plaintext Hasil Dekripsi:**")
                st.code(plaintext_out, language="text")

                # Pengujian N kali waktu dekripsi
                hasil_dec = []
                for i in range(N_dec):
                    _, t_dec = aes_decrypt_cbc(
                        ciphertext_hex_input.strip(),
                        iv_hex_input.strip(),
                        password_dec
                    )
                    hasil_dec.append({
                        "Pengujian Ke-": i + 1,
                        "Waktu Dekripsi (detik)": t_dec
                    })

                df_dec = pd.DataFrame(hasil_dec)
                rata2_dec = df_dec["Waktu Dekripsi (detik)"].mean()

                st.markdown("### 📊 Tabel Hasil Pengujian Dekripsi AES")
                st.dataframe(df_dec, use_container_width=True)

                st.info(f"⏱ Rata-rata waktu dekripsi: `{rata2_dec:.6f}` detik")

            except ValueError:
                st.error(
                    "Dekripsi gagal: kemungkinan password salah, "
                    "IV tidak sesuai, atau ciphertext rusak (padding error)."
                )
            except Exception as e:
                st.error(f"Terjadi kesalahan saat dekripsi/pengujian: {e}")
