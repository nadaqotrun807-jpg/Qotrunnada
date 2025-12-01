# hybrid_aes_rsa_simulasi.py
# Jalankan dengan:
#   pip install streamlit pycryptodome
#   streamlit run hybrid_aes_rsa_simulasi.py

import streamlit as st
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import time

# =========================
# Konfigurasi Halaman
# =========================
st.set_page_config(page_title="Simulasi Hybrid AES–RSA", layout="wide")
st.title("Simulasi Enkripsi–Dekripsi Hybrid AES–RSA dengan Pengulangan Uji")

st.markdown(
    """
Aplikasi ini mensimulasikan skema hybrid cryptography:

- **Enkripsi**:  
  \\( C_{text} = E_{AES}(K_{AES}, P) \\)  
  \\( C_{key} = E_{RSA}(K_{pub}, K_{AES}) \\)

- **Dekripsi**:  
  \\( K_{AES}' = D_{RSA}(K_{priv}, C_{key}) \\)  
  \\( P' = D_{AES}(K_{AES}', C_{text}) \\)  

Dengan pengulangan uji \\( N \\) kali untuk menghitung rata-rata waktu enkripsi dan dekripsi.
"""
)

# =========================
# Sidebar: Pengaturan Simulasi
# =========================
st.sidebar.header("Pengaturan Simulasi")

rsa_bits = st.sidebar.selectbox(
    "Panjang kunci RSA (bit)",
    options=[2048, 3072, 4096],
    index=0,
    help="RSA 2048 bit sudah cukup kuat untuk simulasi."
)

aes_bits = 128  # sesuai judul: AES-128
st.sidebar.write(f"Panjang kunci AES: **{aes_bits} bit** (tetap)")

N = st.sidebar.number_input(
    "Jumlah pengulangan uji (N)",
    min_value=1,
    max_value=100,
    value=5,
    step=1,
    help="Setiap uji menggunakan kunci AES dan nonce baru, dengan plaintext yang sama."
)

st.sidebar.markdown("---")
st.sidebar.caption("Hybrid AES–RSA • Simulasi akademik untuk skripsi.")

# =========================
# Input Plaintext
# =========================
st.subheader("Input Pesan Teks (Plaintext)")

default_text = "Ini adalah contoh pesan teks untuk simulasi hybrid AES–RSA."
plaintext = st.text_area(
    "Masukkan plaintext (P):",
    value=default_text,
    height=120,
)

col_run1, col_run2 = st.columns([1, 3])
with col_run1:
    run_button = st.button("Jalankan Enkripsi dan Dekripsi")

# =========================
# Proses Simulasi
# =========================
if run_button:
    if not plaintext:
        st.warning("Silakan isi plaintext terlebih dahulu.")
    else:
        P_bytes = plaintext.encode("utf-8")

        # =========================
        # 1. Generate Pasangan Kunci RSA
        # =========================
        start_keygen = time.perf_counter()
        rsa_key = RSA.generate(rsa_bits)
        end_keygen = time.perf_counter()

        K_priv = rsa_key
        K_pub = rsa_key.publickey()

        priv_pem = K_priv.export_key().decode("ascii")
        pub_pem = K_pub.export_key().decode("ascii")

        # =========================
        # 2. Pengulangan Uji N kali
        # =========================
        T_enc_list = []  # waktu enkripsi total (AES + RSA)
        T_dec_list = []  # waktu dekripsi total (RSA + AES)

        last_result = {}  # untuk menyimpan hasil uji terakhir, ditampilkan ke pengguna

        for i in range(N):
            # --- Generate kunci AES 128-bit secara acak ---
            K_AES = get_random_bytes(16)  # 16 byte = 128 bit

            # -----------------------------
            # ENKRIPSI (AES + RSA)
            # -----------------------------
            t_enc_start = time.perf_counter()

            # AES-GCM: enkripsi plaintext
            cipher_aes = AES.new(K_AES, AES.MODE_GCM)
            C_text, tag = cipher_aes.encrypt_and_digest(P_bytes)
            nonce = cipher_aes.nonce

            # RSA-OAEP: enkripsi kunci AES
            cipher_rsa_enc = PKCS1_OAEP.new(K_pub, hashAlgo=SHA256)
            C_key = cipher_rsa_enc.encrypt(K_AES)

            t_enc_end = time.perf_counter()
            T_enc = t_enc_end - t_enc_start
            T_enc_list.append(T_enc)

            # -----------------------------
            # DEKRIPSI (RSA + AES)
            # -----------------------------
            t_dec_start = time.perf_counter()

            # RSA-OAEP: dekripsi kunci AES
            cipher_rsa_dec = PKCS1_OAEP.new(K_priv, hashAlgo=SHA256)
            K_AES_rec = cipher_rsa_dec.decrypt(C_key)

            # AES-GCM: dekripsi ciphertext
            cipher_aes_dec = AES.new(K_AES_rec, AES.MODE_GCM, nonce=nonce)
            P_rec_bytes = cipher_aes_dec.decrypt_and_verify(C_text, tag)
            P_rec = P_rec_bytes.decode("utf-8", errors="replace")

            t_dec_end = time.perf_counter()
            T_dec = t_dec_end - t_dec_start
            T_dec_list.append(T_dec)

            # Simpan hasil uji terakhir (untuk ditampilkan rinci)
            if i == N - 1:
                last_result = {
                    "K_AES": K_AES,
                    "C_text": C_text,
                    "C_key": C_key,
                    "nonce": nonce,
                    "tag": tag,
                    "P_rec": P_rec,
                }

        # =========================
        # 3. Perhitungan Statistik Waktu
        # =========================
        avg_T_enc = sum(T_enc_list) / len(T_enc_list)
        avg_T_dec = sum(T_dec_list) / len(T_dec_list)

        min_T_enc = min(T_enc_list)
        max_T_enc = max(T_enc_list)
        min_T_dec = min(T_dec_list)
        max_T_dec = max(T_dec_list)

        # =========================
        # 4. Tampilkan Hasil
        # =========================

        # ---- Kunci RSA ----
        st.subheader("Pasangan Kunci RSA")

        col_key1, col_key2 = st.columns(2)
        with col_key1:
            st.markdown("**Kunci Publik (K_pub)**")
            st.code(pub_pem, language="text")
        with col_key2:
            st.markdown("**Kunci Privat (K_priv)**")
            st.code(priv_pem, language="text")

        st.caption(
            f"Waktu pembangkitan kunci RSA {rsa_bits}-bit: "
            f"{(end_keygen - start_keygen)*1000:.3f} ms"
        )

        st.markdown("---")

        # ---- Ringkasan Waktu Enkripsi/Dekripsi ----
        st.subheader("Ringkasan Pengulangan Uji Waktu Komputasi")

        st.latex(r"\bar{T}_{enc} = \frac{1}{N} \sum_{i=1}^{N} T_{enc}^{(i)}")
        st.latex(r"\bar{T}_{dec} = \frac{1}{N} \sum_{i=1}^{N} T_{dec}^{(i)}")

        col_stat1, col_stat2 = st.columns(2)

        with col_stat1:
            st.markdown("**Enkripsi (AES + RSA)**")
            st.write(f"Jumlah uji (N): **{N}**")
            st.write(f"Rata-rata waktu enkripsi: **{avg_T_enc*1000:.3f} ms**")
            st.write(f"Minimum: {min_T_enc*1000:.3f} ms")
            st.write(f"Maksimum: {max_T_enc*1000:.3f} ms")

        with col_stat2:
            st.markdown("**Dekripsi (RSA + AES)**")
            st.write(f"Jumlah uji (N): **{N}**")
            st.write(f"Rata-rata waktu dekripsi: **{avg_T_dec*1000:.3f} ms**")
            st.write(f"Minimum: {min_T_dec*1000:.3f} ms")
            st.write(f"Maksimum: {max_T_dec*1000:.3f} ms")

        st.markdown("---")

        # ---- Detail Hasil Uji Terakhir ----
        st.subheader("Detail Hasil Uji Terakhir (Uji ke-N)")

        col_enc, col_dec = st.columns(2)

        with col_enc:
            st.markdown("### Proses Enkripsi")
            st.markdown("**Plaintext (P)**")
            st.code(plaintext, language="text")

            st.markdown("**Kunci AES (K_AES) 128-bit (hex)**")
            st.code(last_result["K_AES"].hex(), language="text")

            st.markdown("**Ciphertext (C_text) (hex)**")
            st.code(last_result["C_text"].hex(), language="text")

            st.markdown("**Cipherkey (C_key = kunci AES terenkripsi RSA) (hex)**")
            st.code(last_result["C_key"].hex(), language="text")

            st.markdown("**Parameter AES-GCM**")
            st.write("Nonce (hex):")
            st.code(last_result["nonce"].hex(), language="text")
            st.write("Tag (hex):")
            st.code(last_result["tag"].hex(), language="text")

        with col_dec:
            st.markdown("### Proses Dekripsi")
            st.markdown("**Kunci AES hasil dekripsi RSA (K_AES')**")
            st.code(last_result["K_AES"].hex(), language="text")

            st.markdown("**Plaintext hasil dekripsi (P')**")
            st.code(last_result["P_rec"], language="text")

            # Validasi P' = P
            if last_result["P_rec"] == plaintext:
                st.success("Validasi berhasil: P' = P (plaintext kembali sama persis).")
            else:
                st.error("Validasi gagal: P' ≠ P (ada ketidaksesuaian pada hasil dekripsi).")

        st.markdown("---")
        st.caption(
            "Catatan: setiap uji menggunakan kunci AES dan nonce baru, namun pasangan kunci RSA tetap sama. "
            "Hal ini sesuai dengan skenario sistem di mana server/receiver memiliki kunci RSA tetap, "
            "sedangkan kunci AES dibangkitkan per sesi/pesan."
        )
