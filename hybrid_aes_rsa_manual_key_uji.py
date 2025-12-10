# hybrid_aes_rsa_cbc_uji.py
# Jalankan dengan:
#   pip install streamlit pycryptodome pandas
#   streamlit run hybrid_aes_rsa_cbc_uji.py

import streamlit as st
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
import time
import pandas as pd

# =========================
# Konfigurasi Halaman
# =========================
st.set_page_config(
    page_title="Hybrid AES–RSA (AES-CBC) – Enkripsi, Dekripsi & Pengujian Waktu",
    layout="wide"
)

st.title("🔐 Simulasi Hybrid AES–RSA (AES-128 CBC) dengan Pengujian Waktu N Kali")

st.write(
    """
    Aplikasi ini mensimulasikan skema **hybrid cryptography** dengan:
    
    - **AES-128 dalam mode CBC** untuk enkripsi isi pesan teks (plaintext),
    - **RSA (2048/3072/4096 bit)** dengan skema **OAEP-SHA256** untuk enkripsi kunci AES,
    - Fitur **pengulangan uji (N kali)** untuk mengukur waktu komputasi enkripsi dan dekripsi.
    
    Output utama:
    - Ciphertext AES (C_text),
    - Cipherkey RSA (C_key, yaitu kunci AES yang sudah dienkripsi RSA),
    - IV (Initialization Vector) AES,
    - Tabel waktu enkripsi dan dekripsi beserta rata-ratanya.
    """
)

# =========================
# Sidebar: Pengaturan Uji
# =========================
st.sidebar.header("⚙️ Pengaturan Uji Hybrid")

N = st.sidebar.number_input(
    "Jumlah pengulangan uji (N)",
    min_value=1,
    max_value=100,
    value=5,
    step=1,
    help="Setiap uji memakai plaintext dan kunci AES yang sama, dengan IV baru pada setiap enkripsi."
)

rsa_bits = st.sidebar.selectbox(
    "Panjang kunci RSA (bit)",
    options=[2048, 3072, 4096],
    index=0,
    help="RSA 2048 bit sudah cukup untuk simulasi skripsi. 3072 atau 4096 bit digunakan untuk keamanan yang lebih tinggi."
)

st.sidebar.caption("RSA digunakan untuk enkripsi kunci AES (K_AES), sedangkan AES-128 CBC digunakan untuk enkripsi pesan teks.")

# =========================
# Generate RSA sekali, simpan di session_state
# =========================
if "rsa_key" not in st.session_state or st.session_state.get("rsa_bits") != rsa_bits:
    rsa_key = RSA.generate(rsa_bits)
    st.session_state.rsa_key = rsa_key
    st.session_state.rsa_bits = rsa_bits
    st.session_state.pub_pem = rsa_key.publickey().export_key().decode()
    st.session_state.priv_pem = rsa_key.export_key().decode()
    # reset hasil jika ganti kunci RSA
    st.session_state.runs = []
    st.session_state.T_enc_list = []
    st.session_state.T_dec_list = []
    st.session_state.plaintext = ""
    st.session_state.aes_key_hex = ""

# =========================
# Tampilkan kunci publik & privat RSA (opsional, dalam expander)
# =========================
with st.expander("🔑 Tampilkan Kunci Publik & Privat RSA (PEM)"):
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Kunci Publik (K_pub)**")
        st.code(st.session_state.pub_pem, language="text")
    with col2:
        st.markdown("**Kunci Privat (K_priv)**")
        st.code(st.session_state.priv_pem, language="text")

st.markdown("---")

# =========================
# 1. Generate & Input Kunci AES
# =========================
st.subheader("1. Kunci AES 128-bit (K_AES)")

if "aes_key_hex" not in st.session_state:
    st.session_state.aes_key_hex = ""

col_aes1, col_aes2 = st.columns([1, 3])

with col_aes1:
    if st.button("🔑 Generate Kunci AES 128-bit"):
        key_bytes = get_random_bytes(16)   # 16 byte = 128 bit
        st.session_state.aes_key_hex = key_bytes.hex()

with col_aes2:
    aes_key_hex = st.text_input(
        "Kunci AES (hex) – 32 karakter hex (16 byte = 128 bit):",
        value=st.session_state.aes_key_hex,
        help="Kunci dapat digenerate otomatis atau diisi manual. Panjang harus 32 karakter hex."
    )
    # sinkronkan ke session_state
    st.session_state.aes_key_hex = aes_key_hex

st.info(
    "Pada skema hybrid, kunci ini **tidak dikirim apa adanya**. "
    "K_AES akan dienkripsi menggunakan RSA sehingga menjadi Cipherkey (C_key)."
)

st.markdown("---")

# =========================
# 2. Input Plaintext
# =========================
st.subheader("2. Input Plaintext (Pesan Teks)")

plaintext = st.text_area(
    "Masukkan Plaintext (P):",
    value=st.session_state.get(
        "plaintext",
        "Hybrid AES–RSA digunakan untuk melindungi pesan teks pada sistem komunikasi digital."
    ),
    height=120,
    help="Plaintext akan dienkode ke UTF-8, dipadding (PKCS7), lalu dienkripsi dengan AES-128 CBC."
)

# Tombol aksi utama
col_btn1, col_btn2 = st.columns(2)
btn_encrypt = col_btn1.button("🔒 Enkripsi Hybrid (AES-CBC + RSA) – Uji N Kali")
btn_decrypt = col_btn2.button("🔓 Dekripsi Hybrid (RSA + AES-CBC) – Uji N Kali")

st.markdown("---")

# =========================
# Fungsi Enkripsi & Dekripsi Hybrid
# =========================

def hybrid_encrypt_once(K_AES: bytes, P_bytes: bytes, rsa_key_obj: RSA.RsaKey):
    """
    Enkripsi satu kali:
    - AES-128 CBC untuk plaintext (dengan IV acak + padding),
    - RSA-OAEP (SHA-256) untuk kunci AES.
    """
    # Padding plaintext ke kelipatan 16 byte
    P_padded = pad(P_bytes, AES.block_size)

    # AES-CBC: generate IV acak dan enkripsi
    iv = get_random_bytes(16)
    cipher_aes = AES.new(K_AES, AES.MODE_CBC, iv=iv)
    C_text = cipher_aes.encrypt(P_padded)

    # RSA: enkripsi kunci AES dengan kunci publik
    cipher_rsa = PKCS1_OAEP.new(rsa_key_obj.publickey(), hashAlgo=SHA256)
    C_key = cipher_rsa.encrypt(K_AES)

    return C_text, C_key, iv


def hybrid_decrypt_once(C_text: bytes, C_key: bytes, iv: bytes, rsa_key_obj: RSA.RsaKey):
    """
    Dekripsi satu kali:
    - Dekripsi RSA untuk mendapatkan kembali K_AES,
    - Dekripsi AES-128 CBC (dengan IV) untuk mengembalikan plaintext.
    """
    # RSA: dekripsi kunci AES
    cipher_rsa_dec = PKCS1_OAEP.new(rsa_key_obj, hashAlgo=SHA256)
    K_AES_rec = cipher_rsa_dec.decrypt(C_key)

    # AES-CBC: dekripsi ciphertext
    cipher_aes_dec = AES.new(K_AES_rec, AES.MODE_CBC, iv=iv)
    P_padded_rec = cipher_aes_dec.decrypt(C_text)
    P_rec_bytes = unpad(P_padded_rec, AES.block_size)

    return K_AES_rec, P_rec_bytes

# =========================
# 3. PROSES ENKRIPSI HYBRID (AES-CBC + RSA) N kali
# =========================
if btn_encrypt:
    if not plaintext:
        st.warning("Plaintext belum diisi.")
    elif not aes_key_hex:
        st.warning("Kunci AES (hex) belum diisi.")
    else:
        try:
            K_AES = bytes.fromhex(aes_key_hex.strip())
        except ValueError:
            K_AES = None

        if K_AES is None or len(K_AES) != 16:
            st.error("Kunci AES tidak valid. Pastikan 32 karakter hex (16 byte = 128-bit).")
        else:
            st.session_state.plaintext = plaintext  # simpan plaintext referensi
            P_bytes = plaintext.encode("utf-8")

            runs = []
            T_enc_list = []

            for i in range(N):
                t_enc_start = time.perf_counter()

                C_text, C_key, iv = hybrid_encrypt_once(K_AES, P_bytes, st.session_state.rsa_key)

                t_enc_end = time.perf_counter()
                T_enc = t_enc_end - t_enc_start
                T_enc_list.append(T_enc)

                runs.append({
                    "K_AES": K_AES,
                    "C_text": C_text,
                    "C_key": C_key,
                    "iv": iv,
                })

            # Simpan ke session_state untuk dipakai dekripsi
            st.session_state.runs = runs
            st.session_state.T_enc_list = T_enc_list
            st.session_state.T_dec_list = []

            st.success(f"Enkripsi hybrid selesai. Dilakukan {N} kali uji.")

            # ===== TABEL HASIL UJI ENKRIPSI =====
            df_enc = pd.DataFrame({
                "Uji ke-": list(range(1, N + 1)),
                "T_enc (detik)": T_enc_list,
            })

            st.markdown("### 📊 Tabel Hasil Uji Enkripsi Hybrid (N kali)")
            st.dataframe(df_enc, use_container_width=True)

            # ===== Statistik Enkripsi =====
            avg_T_enc = sum(T_enc_list) / len(T_enc_list)
            st.markdown("### 📈 Statistik Waktu Enkripsi Hybrid")
            st.write(f"Rata-rata waktu enkripsi: **{avg_T_enc:.6f} detik**")
            st.write(f"Minimum waktu enkripsi: `{min(T_enc_list):.6f}` detik")
            st.write(f"Maksimum waktu enkripsi: `{max(T_enc_list):.6f}` detik")

            # Contoh hasil uji terakhir
            last = runs[-1]
            st.markdown("### 📌 Contoh Hasil Enkripsi pada Uji ke-N")

            st.write("**K_AES (hex)**")
            st.code(last["K_AES"].hex(), language="text")

            st.write("**Ciphertext (C_text) – hex**")
            st.code(last["C_text"].hex(), language="text")

            st.write("**Cipherkey (C_key) terenkripsi RSA – hex**")
            st.code(last["C_key"].hex(), language="text")

            st.write("**IV (Initialization Vector) – hex**")
            st.code(last["iv"].hex(), language="text")

            st.info(
                "Ciphertext (C_text) dan Cipherkey (C_key) inilah yang akan "
                "ditransmisikan pada skema hybrid. IV juga perlu disimpan/dikirim "
                "bersama ciphertext untuk proses dekripsi."
            )

# =========================
# 4. PROSES DEKRIPSI HYBRID (RSA + AES-CBC) N kali
# =========================
if btn_decrypt:
    runs = st.session_state.get("runs", [])
    plaintext_saved = st.session_state.get("plaintext", "")

    if not runs:
        st.warning("Belum ada data enkripsi. Jalankan dulu tombol ENKRIPSI HYBRID.")
    elif not plaintext_saved:
        st.warning("Plaintext referensi belum tersimpan.")
    else:
        P_bytes_ref = plaintext_saved.encode("utf-8")
        T_dec_list = []
        status_list = []
        P_rec_list = []
        k_aes_rec_hex_list = []

        for i, r in enumerate(runs):
            t_dec_start = time.perf_counter()

            K_AES_rec, P_rec_bytes = hybrid_decrypt_once(
                r["C_text"], r["C_key"], r["iv"], st.session_state.rsa_key
            )
            P_rec = P_rec_bytes.decode("utf-8", errors="replace")
            k_aes_rec_hex_list.append(K_AES_rec.hex())

            t_dec_end = time.perf_counter()
            T_dec = t_dec_end - t_dec_start
            T_dec_list.append(T_dec)

            status = "P' = P (valid)" if P_rec_bytes == P_bytes_ref else "Tidak cocok"
            status_list.append(status)
            P_rec_list.append(P_rec)

        st.session_state.T_dec_list = T_dec_list

        st.success(f"Dekripsi hybrid selesai. Dilakukan {len(runs)} kali uji.")

        # ===== TABEL HASIL UJI DEKRIPSI =====
        df_dec = pd.DataFrame({
            "Uji ke-": list(range(1, len(runs) + 1)),
            "T_dec (detik)": T_dec_list,
            "K_AES_rec (hex)": k_aes_rec_hex_list,
            "Status": status_list,
        })

        st.markdown("### 📊 Tabel Hasil Uji Dekripsi Hybrid (N kali)")
        st.dataframe(df_dec, use_container_width=True)

        # ===== Statistik Dekripsi =====
        avg_T_dec = sum(T_dec_list) / len(T_dec_list)
        st.markdown("### 📉 Statistik Waktu Dekripsi Hybrid")
        st.write(f"Rata-rata waktu dekripsi: **{avg_T_dec:.6f} detik**")
        st.write(f"Minimum waktu dekripsi: `{min(T_dec_list):.6f}` detik")
        st.write(f"Maksimum waktu dekripsi: `{max(T_dec_list):.6f}` detik")

        # Plaintext hasil dekripsi uji terakhir
        st.markdown("### 📜 Plaintext Hasil Dekripsi (Uji ke-N)")
        st.code(P_rec_list[-1], language="text")

        # Validasi global
        if all(s == "P' = P (valid)" for s in status_list):
            st.success("Semua uji valid: P' = P pada setiap pengulangan.")
        else:
            st.error("Ada uji yang tidak valid (P' ≠ P). Periksa kembali data atau implementasi.")
