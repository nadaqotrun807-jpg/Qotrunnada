# hybrid_aes_rsa_uji.py
# Jalankan:
#   pip install streamlit pycryptodome pandas
#   streamlit run hybrid_aes_rsa_uji.py

import streamlit as st
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import time
import pandas as pd

st.set_page_config(page_title="Simulasi Hybrid AES–RSA", layout="wide")
st.title("Simulasi Enkripsi–Dekripsi Hybrid AES–RSA dengan Pengulangan Uji")

# =========================
# Sidebar: Pengaturan Uji
# =========================
st.sidebar.header("Pengaturan Uji")
N = st.sidebar.number_input(
    "Jumlah pengulangan uji (N)",
    min_value=1,
    max_value=100,
    value=5,
    step=1,
    help="Setiap uji menggunakan kunci AES dan nonce baru."
)

rsa_bits = st.sidebar.selectbox(
    "Panjang kunci RSA (bit)",
    options=[2048, 3072, 4096],
    index=0
)

st.sidebar.caption("RSA untuk distribusi kunci, AES-128 untuk enkripsi data.")

# =========================
# Generate RSA sekali, simpan di session_state
# =========================
if "rsa_key" not in st.session_state or st.session_state.get("rsa_bits") != rsa_bits:
    rsa_key = RSA.generate(rsa_bits)
    st.session_state.rsa_key = rsa_key
    st.session_state.rsa_bits = rsa_bits
    st.session_state.pub_pem = rsa_key.publickey().export_key().decode()
    st.session_state.priv_pem = rsa_key.export_key().decode()
    # reset hasil jika kunci baru
    st.session_state.runs = []
    st.session_state.T_enc_list = []
    st.session_state.T_dec_list = []
    st.session_state.plaintext = ""

# =========================
# Tampilkan kunci publik & privat
# =========================
with st.expander("🔐 Tampilkan Kunci Publik & Privat RSA"):
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Kunci Publik (K_pub)**")
        st.code(st.session_state.pub_pem, language="text")
    with col2:
        st.markdown("**Kunci Privat (K_priv)**")
        st.code(st.session_state.priv_pem, language="text")

# =========================
# Input Plaintext
# =========================
st.subheader("Input Pesan Teks (Plaintext)")
plaintext = st.text_area(
    "Masukkan Plaintext (P):",
    value=st.session_state.get("plaintext", "Ini adalah contoh pesan teks untuk simulasi."),
    height=120,
)

col_btn1, col_btn2 = st.columns(2)
btn_encrypt = col_btn1.button("🔒 Jalankan Enkripsi (N kali)")
btn_decrypt = col_btn2.button("🔓 Jalankan Dekripsi (N kali)")

# =========================
# PROSES ENKRIPSI (N kali)
# =========================
if btn_encrypt:
    if not plaintext:
        st.warning("Masukkan plaintext terlebih dahulu.")
    else:
        st.session_state.plaintext = plaintext
        P_bytes = plaintext.encode("utf-8")

        runs = []
        T_enc_list = []

        for i in range(N):
            # Generate kunci AES 128-bit
            K_AES = get_random_bytes(16)  # 128-bit

            t_enc_start = time.perf_counter()

            # AES-GCM: enkripsi plaintext
            cipher_aes = AES.new(K_AES, AES.MODE_GCM)
            C_text, tag = cipher_aes.encrypt_and_digest(P_bytes)
            nonce = cipher_aes.nonce

            # RSA-OAEP: enkripsi kunci AES
            cipher_rsa = PKCS1_OAEP.new(st.session_state.rsa_key.publickey(), hashAlgo=SHA256)
            C_key = cipher_rsa.encrypt(K_AES)

            t_enc_end = time.perf_counter()
            T_enc = t_enc_end - t_enc_start
            T_enc_list.append(T_enc)

            runs.append({
                "K_AES": K_AES,
                "C_text": C_text,
                "C_key": C_key,
                "nonce": nonce,
                "tag": tag,
            })

        # Simpan ke session_state untuk dipakai tombol Dekripsi
        st.session_state.runs = runs
        st.session_state.T_enc_list = T_enc_list
        st.session_state.T_dec_list = []  # reset hasil dekripsi lama

        st.success(f"Enkripsi selesai. Dilakukan {N} kali uji.")

        # =========================
        # TABEL HASIL UJI ENKRIPSI
        # =========================
        df_enc = pd.DataFrame({
            "Uji ke-": list(range(1, N + 1)),
            "T_enc (ms)": [t * 1000 for t in T_enc_list],
        })

        st.markdown("### Tabel Hasil Uji Enkripsi (N kali)")
        st.dataframe(df_enc, use_container_width=True)

        st.markdown("### Statistik Waktu Enkripsi")
        avg_T_enc = sum(T_enc_list) / len(T_enc_list)
        st.write(f"Rata-rata waktu enkripsi: **{avg_T_enc * 1000:.3f} ms**")
        st.write(f"Minimum: {min(T_enc_list) * 1000:.3f} ms")
        st.write(f"Maksimum: {max(T_enc_list) * 1000:.3f} ms")

        # Tampilkan detail uji terakhir sebagai contoh
        last = runs[-1]
        st.markdown("### Contoh Hasil Uji Terakhir (Uji ke-N)")
        st.write("**K_AES (hex)**")
        st.code(last["K_AES"].hex(), language="text")
        st.write("**Ciphertext (C_text) (hex)**")
        st.code(last["C_text"].hex(), language="text")
        st.write("**Cipherkey (C_key) terenkripsi RSA (hex)**")
        st.code(last["C_key"].hex(), language="text")
        st.write("**Nonce (hex)**")
        st.code(last["nonce"].hex(), language="text")
        st.write("**Tag (hex)**")
        st.code(last["tag"].hex(), language="text")

# =========================
# PROSES DEKRIPSI (N kali)
# =========================
if btn_decrypt:
    runs = st.session_state.get("runs", [])
    plaintext_saved = st.session_state.get("plaintext", "")

    if not runs:
        st.warning("Belum ada data enkripsi. Jalankan dulu tombol ENKRIPSI.")
    else:
        P_bytes_ref = plaintext_saved.encode("utf-8")
        T_dec_list = []
        status_list = []
        P_rec_list = []

        for i, r in enumerate(runs):
            t_dec_start = time.perf_counter()

            # Dekripsi kunci AES dengan RSA
            cipher_rsa_dec = PKCS1_OAEP.new(st.session_state.rsa_key, hashAlgo=SHA256)
            K_AES_rec = cipher_rsa_dec.decrypt(r["C_key"])

            # Dekripsi ciphertext dengan AES-GCM
            cipher_aes_dec = AES.new(K_AES_rec, AES.MODE_GCM, nonce=r["nonce"])
            P_rec_bytes = cipher_aes_dec.decrypt_and_verify(r["C_text"], r["tag"])
            P_rec = P_rec_bytes.decode("utf-8", errors="replace")

            t_dec_end = time.perf_counter()
            T_dec = t_dec_end - t_dec_start
            T_dec_list.append(T_dec)

            # validasi
            status = "P' = P (valid)" if P_rec_bytes == P_bytes_ref else "Tidak cocok"
            status_list.append(status)
            P_rec_list.append(P_rec)

        st.session_state.T_dec_list = T_dec_list

        st.success(f"Dekripsi selesai. Dilakukan {len(runs)} kali uji.")

        # =========================
        # TABEL HASIL UJI DEKRIPSI
        # =========================
        df_dec = pd.DataFrame({
            "Uji ke-": list(range(1, len(runs) + 1)),
            "T_dec (ms)": [t * 1000 for t in T_dec_list],
            "Status": status_list,
        })

        st.markdown("### Tabel Hasil Uji Dekripsi (N kali)")
        st.dataframe(df_dec, use_container_width=True)

        st.markdown("### Statistik Waktu Dekripsi")
        avg_T_dec = sum(T_dec_list) / len(T_dec_list)
        st.write(f"Rata-rata waktu dekripsi: **{avg_T_dec * 1000:.3f} ms**")
        st.write(f"Minimum: {min(T_dec_list) * 1000:.3f} ms")
        st.write(f"Maksimum: {max(T_dec_list) * 1000:.3f} ms")

        # Tampilkan plaintext hasil dekripsi uji terakhir
        st.markdown("### Plaintext Hasil Dekripsi (Uji ke-N)")
        st.code(P_rec_list[-1], language="text")

        # Validasi umum
        if all(s == "P' = P (valid)" for s in status_list):
            st.success("Semua uji: P' = P. Implementasi dekripsi konsisten.")
        else:
            st.error("Ada uji yang tidak valid (P' ≠ P). Periksa data atau implementasi.")
