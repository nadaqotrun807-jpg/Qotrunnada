import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import hashlib
import time
import pandas as pd

# =========================
# Fungsi Utilitas AES
# =========================

def derive_key_from_password(password: str) -> bytes:
    """
    Mengubah password (string) menjadi kunci AES 128-bit.
    Password di-hash dengan SHA-256, lalu diambil 16 byte pertama (128 bit).
    """
    if not password:
        raise ValueError("Password tidak boleh kosong.")
    sha256_hash = hashlib.sha256(password.encode("utf-8")).digest()
    return sha256_hash[:16]  # 16 byte = 128 bit


def aes_encrypt_gcm(plaintext: str, key: bytes):
    """
    Enkripsi AES-128 GCM.
    Output: ciphertext_hex, nonce_hex, tag_hex, waktu_enkripsi
    """
    plaintext_bytes = plaintext.encode("utf-8")

    t_start = time.perf_counter()
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext_bytes, tag_bytes = cipher.encrypt_and_digest(plaintext_bytes)
    t_end = time.perf_counter()

    nonce_bytes = cipher.nonce

    return (
        ciphertext_bytes.hex(),
        nonce_bytes.hex(),
        tag_bytes.hex(),
        t_end - t_start,
    )


def aes_decrypt_gcm(ciphertext_hex: str, nonce_hex: str, tag_hex: str, key: bytes):
    """
    Dekripsi AES-128 GCM.
    Output: plaintext_str, waktu_dekripsi
    """
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)
    nonce_bytes = bytes.fromhex(nonce_hex)
    tag_bytes = bytes.fromhex(tag_hex)

    t_start = time.perf_counter()
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce_bytes)
    plaintext_bytes = cipher.decrypt_and_verify(ciphertext_bytes, tag_bytes)
    t_end = time.perf_counter()

    return plaintext_bytes.decode("utf-8"), (t_end - t_start)


# =========================
# Fungsi Utilitas RSA
# =========================

def generate_rsa_keypair(bits: int = 2048):
    """
    Membangkitan sepasang kunci RSA (privat & publik) dalam format PEM.
    """
    key = RSA.generate(bits)
    private_key_pem = key.export_key().decode("utf-8")
    public_key_pem = key.publickey().export_key().decode("utf-8")
    return private_key_pem, public_key_pem


def rsa_encrypt_oaep(plaintext_bytes: bytes, public_key_pem: str):
    """
    Enkripsi RSA-OAEP (PKCS1_OAEP + SHA-256).
    Input: bytes (bisa plaintext atau kunci AES).
    Output: ciphertext_hex, waktu_enkripsi
    """
    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)

    t_start = time.perf_counter()
    ciphertext_bytes = cipher.encrypt(plaintext_bytes)
    t_end = time.perf_counter()

    return ciphertext_bytes.hex(), (t_end - t_start)


def rsa_decrypt_oaep(ciphertext_hex: str, private_key_pem: str):
    """
    Dekripsi RSA-OAEP.
    Output: plaintext_bytes, waktu_dekripsi
    """
    private_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)

    t_start = time.perf_counter()
    plaintext_bytes = cipher.decrypt(ciphertext_bytes)
    t_end = time.perf_counter()

    return plaintext_bytes, (t_end - t_start)


# =========================
# Hybrid AES–RSA
# =========================

def hybrid_encrypt(plaintext: str, password: str, public_key_pem: str):
    """
    Hybrid:
    - K_AES dibentuk dari password (128-bit)
    - AES-128 GCM untuk mengenkripsi plaintext
    - RSA-OAEP untuk mengenkripsi K_AES
    Waktu enkripsi = waktu AES + waktu RSA.
    """
    k_aes = derive_key_from_password(password)

    # AES untuk plaintext
    ctext_hex, nonce_hex, tag_hex, t_aes = aes_encrypt_gcm(plaintext, k_aes)

    # RSA untuk kunci AES (16 byte)
    ckey_hex, t_rsa = rsa_encrypt_oaep(k_aes, public_key_pem)

    total_time = t_aes + t_rsa
    return ctext_hex, nonce_hex, tag_hex, ckey_hex, total_time, t_aes, t_rsa


def hybrid_decrypt(ctext_hex: str, nonce_hex: str, tag_hex: str,
                   ckey_hex: str, password: str, private_key_pem: str):
    """
    Hybrid dekripsi:
    - RSA-OAEP untuk mendapatkan kembali K_AES
    - AES-128 GCM untuk mendekripsi ciphertext
    Waktu dekripsi = waktu RSA + waktu AES.
    """
    # RSA untuk kunci AES
    k_aes_bytes, t_rsa_dec = rsa_decrypt_oaep(ckey_hex, private_key_pem)

    # Tambahan validasi (opsional): bandingkan dengan derive password
    # agar secara konsep tetap mengikuti password yang sama.
    # Namun untuk simulasi waktu, ini tidak mempengaruhi.

    # AES untuk plaintext
    plaintext_out, t_aes_dec = aes_decrypt_gcm(ctext_hex, nonce_hex, tag_hex, k_aes_bytes)

    total_time = t_rsa_dec + t_aes_dec
    return plaintext_out, total_time, t_aes_dec, t_rsa_dec


# =========================
# Streamlit App
# =========================

st.set_page_config(
    page_title="Perbandingan AES vs RSA vs Hybrid",
    layout="centered"
)

st.title("🔐 Perbandingan Waktu AES Tunggal, RSA Tunggal, dan Hybrid AES–RSA")

st.write(
    """
    Aplikasi ini melakukan pengujian **waktu enkripsi dan dekripsi** untuk tiga skema:
    
    1. **AES Tunggal (AES-128 GCM)** – kunci dari password,
    2. **RSA Tunggal (RSA-OAEP)** – mengenkripsi plaintext langsung,
    3. **Hybrid AES–RSA** – AES untuk pesan, RSA untuk kunci AES.
    
    Hasil akhir berupa:
    - Tabel waktu rata-rata enkripsi & dekripsi,
    - Ringkasan perbandingan: **AES vs RSA vs Hybrid**.
    """
)

# ---------------------------
# Input Parameter
# ---------------------------
st.subheader("🎯 Parameter Pengujian")

plaintext = st.text_area(
    "Plaintext yang akan diuji",
    value="Sistem hybrid AES dan RSA digunakan untuk mengamankan pesan teks pada komunikasi digital.",
    height=120
)

password = st.text_input(
    "Password untuk AES & Hybrid (membentuk kunci AES 128-bit)",
    type="password",
    value="passwordku123"
)

col_param1, col_param2 = st.columns(2)

with col_param1:
    N = st.number_input(
        "Jumlah pengujian per skema (N):",
        min_value=1,
        max_value=100,
        value=10,
        step=1
    )

with col_param2:
    rsa_bits = st.selectbox(
        "Panjang kunci RSA:",
        options=[1024, 2048, 3072],
        index=1,
        help="Semakin besar bit, semakin aman namun lebih lambat."
    )

st.markdown("---")

# ---------------------------
# Generate RSA key sekali
# ---------------------------
if "rsa_private_key" not in st.session_state:
    priv_pem, pub_pem = generate_rsa_keypair(bits=rsa_bits)
    st.session_state.rsa_private_key = priv_pem
    st.session_state.rsa_public_key = pub_pem
    st.session_state.rsa_bits = rsa_bits

# Jika user mengganti rsa_bits, regenerasi kunci
if rsa_bits != st.session_state.get("rsa_bits", rsa_bits):
    priv_pem, pub_pem = generate_rsa_keypair(bits=rsa_bits)
    st.session_state.rsa_private_key = priv_pem
    st.session_state.rsa_public_key = pub_pem
    st.session_state.rsa_bits = rsa_bits

with st.expander("🔑 Lihat Kunci RSA (Publik & Privat)"):
    colk1, colk2 = st.columns(2)
    with colk1:
        st.markdown("**Kunci Publik RSA:**")
        st.code(st.session_state.rsa_public_key, language="text")
    with colk2:
        st.markdown("**Kunci Privat RSA:**")
        st.code(st.session_state.rsa_private_key, language="text")

# ---------------------------
# Jalankan Pengujian
# ---------------------------
if st.button("🚀 Jalankan Pengujian Semua Skema"):
    if not plaintext:
        st.error("Plaintext tidak boleh kosong.")
    elif not password:
        st.error("Password untuk AES/Hybrid tidak boleh kosong.")
    else:
        try:
            # =====================
            # 1. AES TUNGGAL
            # =====================
            k_aes = derive_key_from_password(password)

            times_aes_enc = []
            times_aes_dec = []

            # Enkripsi awal untuk mendapatkan ciphertext referensi
            c_aes_hex, nonce_aes_hex, tag_aes_hex, t_enc_first_aes = aes_encrypt_gcm(plaintext, k_aes)

            # Pengujian enkripsi N kali
            for _ in range(N):
                _, _, _, t_enc = aes_encrypt_gcm(plaintext, k_aes)
                times_aes_enc.append(t_enc)

            # Pengujian dekripsi N kali menggunakan ciphertext yang sama
            for _ in range(N):
                _, t_dec = aes_decrypt_gcm(c_aes_hex, nonce_aes_hex, tag_aes_hex, k_aes)
                times_aes_dec.append(t_dec)

            avg_aes_enc = sum(times_aes_enc) / N
            avg_aes_dec = sum(times_aes_dec) / N

            # =====================
            # 2. RSA TUNGGAL
            # =====================
            times_rsa_enc = []
            times_rsa_dec = []

            plaintext_bytes = plaintext.encode("utf-8")

            # Enkripsi awal (untuk ciphertext referensi)
            c_rsa_hex, t_enc_first_rsa = rsa_encrypt_oaep(
                plaintext_bytes,
                st.session_state.rsa_public_key
            )

            # Pengujian enkripsi N kali
            for _ in range(N):
                _, t_enc = rsa_encrypt_oaep(
                    plaintext_bytes,
                    st.session_state.rsa_public_key
                )
                times_rsa_enc.append(t_enc)

            # Pengujian dekripsi N kali
            for _ in range(N):
                _, t_dec = rsa_decrypt_oaep(
                    c_rsa_hex,
                    st.session_state.rsa_private_key
                )
                times_rsa_dec.append(t_dec)

            avg_rsa_enc = sum(times_rsa_enc) / N
            avg_rsa_dec = sum(times_rsa_dec) / N

            # =====================
            # 3. HYBRID AES–RSA
            # =====================
            times_hybrid_enc = []
            times_hybrid_dec = []

            # Enkripsi awal untuk referensi ciphertext dan cipherkey
            (
                c_hyb_hex,
                nonce_hyb_hex,
                tag_hyb_hex,
                ckey_hyb_hex,
                t_hybrid_first,
                _,
                _
            ) = hybrid_encrypt(
                plaintext,
                password,
                st.session_state.rsa_public_key
            )

            # Pengujian enkripsi N kali
            for _ in range(N):
                _, _, _, _, t_total, _, _ = hybrid_encrypt(
                    plaintext,
                    password,
                    st.session_state.rsa_public_key
                )
                times_hybrid_enc.append(t_total)

            # Pengujian dekripsi N kali
            for _ in range(N):
                _, t_total_dec, _, _ = hybrid_decrypt(
                    c_hyb_hex,
                    nonce_hyb_hex,
                    tag_hyb_hex,
                    ckey_hyb_hex,
                    password,
                    st.session_state.rsa_private_key
                )
                times_hybrid_dec.append(t_total_dec)

            avg_hybrid_enc = sum(times_hybrid_enc) / N
            avg_hybrid_dec = sum(times_hybrid_dec) / N

            # =====================
            # Tampilkan Contoh Output
            # =====================
            st.success("Pengujian selesai.")

            with st.expander("📦 Contoh Output Setiap Skema"):
                st.markdown("### AES Tunggal")
                st.markdown("**Ciphertext (hex):**")
                st.code(c_aes_hex, language="text")
                st.markdown("**Nonce (hex):**")
                st.code(nonce_aes_hex, language="text")
                st.markdown("**Tag (hex):**")
                st.code(tag_aes_hex, language="text")

                st.markdown("### RSA Tunggal")
                st.markdown("**Ciphertext (hex):**")
                st.code(c_rsa_hex, language="text")

                st.markdown("### Hybrid AES–RSA")
                st.markdown("**Ciphertext AES (hex):**")
                st.code(c_hyb_hex, language="text")
                st.markdown("**Nonce (hex):**")
                st.code(nonce_hyb_hex, language="text")
                st.markdown("**Tag (hex):**")
                st.code(tag_hyb_hex, language="text")
                st.markdown("**Cipherkey (kunci AES terenkripsi RSA, hex):**")
                st.code(ckey_hyb_hex, language="text")

            # =====================
            # Tabel Rata-rata Waktu (Ringkasan)
            # =====================
            st.markdown("## 📊 Tabel Waktu Rata-Rata (AES vs RSA vs Hybrid)")

            data_ringkasan = {
                "Skema": ["AES Tunggal", "RSA Tunggal", "Hybrid AES–RSA"],
                "Rata-rata Waktu Enkripsi (detik)": [
                    avg_aes_enc,
                    avg_rsa_enc,
                    avg_hybrid_enc
                ],
                "Rata-rata Waktu Dekripsi (detik)": [
                    avg_aes_dec,
                    avg_rsa_dec,
                    avg_hybrid_dec
                ]
            }

            df_ringkasan = pd.DataFrame(data_ringkasan)
            st.dataframe(df_ringkasan, use_container_width=True)

            st.info(
                "Tabel di atas dapat langsung digunakan sebagai dasar pembahasan di BAB IV "
                "untuk membandingkan efisiensi waktu ketiga skema."
            )

        except Exception as e:
            st.error(f"Terjadi kesalahan saat pengujian: {e}")
