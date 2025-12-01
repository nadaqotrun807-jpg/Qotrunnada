# sim_enkripsi_hybrid.py
# pip install streamlit pycryptodome

import streamlit as st
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

st.set_page_config(page_title="Simulasi Enkripsi AES–RSA", layout="centered")
st.title("Simulasi Enkripsi Hybrid AES–RSA")

st.markdown("### Langkah 1: Input Pesan Teks (Plaintext)")
P = st.text_area(
    "Masukkan pesan teks (P):",
    value="Ini contoh pesan teks untuk simulasi.",
    height=120,
)

if st.button("Jalankan Simulasi Enkripsi"):
    if not P:
        st.warning("Silakan isi pesan teks (plaintext) terlebih dahulu.")
    else:
        # ============================
        # Langkah 2: Generate kunci AES (K_AES)
        # ============================
        # Kunci AES 128-bit = 16 byte
        K_AES = get_random_bytes(16)  # 128-bit key

        # ============================
        # Langkah 3: Enkripsi pesan menggunakan AES
        # C_text = E_AES(K_AES, P)
        # ============================
        P_bytes = P.encode("utf-8")

        # Gunakan AES-128 dalam mode GCM (memberikan confidentiality + integrity)
        cipher_aes = AES.new(K_AES, AES.MODE_GCM)
        C_text, tag = cipher_aes.encrypt_and_digest(P_bytes)
        nonce = cipher_aes.nonce

        # ============================
        # Langkah 4: Enkripsi kunci AES menggunakan RSA
        # C_key = E_RSA(K_pub, K_AES)
        # ============================
        # Untuk simulasi, kita generate pasangan kunci RSA (2048-bit)
        rsa_key = RSA.generate(2048)
        K_pub = rsa_key.publickey()

        cipher_rsa = PKCS1_OAEP.new(K_pub, hashAlgo=SHA256)
        C_key = cipher_rsa.encrypt(K_AES)

        # ============================
        # Langkah 5: Output hasil simulasi enkripsi
        # ============================

        st.markdown("## Hasil Simulasi Enkripsi")

        st.markdown("### Notasi Matematis")
        st.latex(r"C_{\text{text}} = E_{\text{AES}}(K_{\text{AES}}, P)")
        st.latex(r"C_{\text{key}} = E_{\text{RSA}}(K_{\text{pub}}, K_{\text{AES}})")

        st.markdown("### Ringkasan Nilai Penting")
        st.code(f"Plaintext (P): {P}", language="text")
        st.code(f"K_AES (128-bit, hex): {K_AES.hex()}", language="text")

        st.markdown("#### Ciphertext (C_text)")
        st.code(C_text.hex(), language="text")

        st.markdown("#### Cipherkey (C_key = kunci AES yang dienkripsi RSA)")
        st.code(C_key.hex(), language="text")

        st.markdown("### Parameter AES-GCM (diperlukan untuk dekripsi)")
        st.code(f"Nonce: {nonce.hex()}", language="text")
        st.code(f"Tag   : {tag.hex()}", language="text")

        st.markdown("### Kunci Publik RSA (K_pub)")
        st.code(K_pub.export_key().decode("ascii"), language="text")

        st.info(
            "Keluaran utama sesuai langkah simulasi enkripsi adalah ciphertext (C_text) "
            "dan cipherkey (C_key). Nonce dan tag AES-GCM juga ditampilkan karena "
            "dibutuhkan saat proses dekripsi."
        )
