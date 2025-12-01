# sim_dekripsi_hybrid.py
# pip install streamlit pycryptodome

import streamlit as st
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

st.set_page_config(page_title="Simulasi Dekripsi AES–RSA", layout="centered")
st.title("Simulasi Dekripsi Hybrid AES–RSA")

st.markdown("### Langkah 1: Input Ciphertext dan Cipherkey")
st.write("Masukkan data output dari proses enkripsi:")

C_text_hex = st.text_area(
    "Ciphertext (C_text) dalam bentuk hex:",
    value="",
    height=80,
    placeholder="contoh: d0fa0976efde3c19..."
)

C_key_hex = st.text_area(
    "Cipherkey (C_key = kunci AES yang dienkripsi RSA) dalam bentuk hex:",
    value="",
    height=120,
    placeholder="contoh: 49021a93ed26e46c..."
)

st.markdown("#### Parameter AES-GCM (diperlukan untuk dekripsi)")
nonce_hex = st.text_input(
    "Nonce (hex):",
    value="",
    placeholder="contoh: 834ceeb35aca36d3698b0c05283a7c1d"
)

tag_hex = st.text_input(
    "Tag (hex):",
    value="",
    placeholder="contoh: 92b8b9d47b961be67a4dfc24b58c7c4b"
)

st.markdown("#### Kunci Privat RSA (K_priv)")
K_priv_pem = st.text_area(
    "Tempelkan kunci privat RSA (PEM):",
    value="",
    height=180,
    placeholder="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
)

st.markdown("### (Opsional) Plaintext Awal untuk Validasi")
P_awal = st.text_input(
    "Masukkan plaintext awal (opsional, untuk cek P' = P):",
    value="",
    placeholder="Jika diisi, sistem akan membandingkan dengan hasil dekripsi."
)

if st.button("Jalankan Simulasi Dekripsi"):
    # Validasi input minimal
    if not C_text_hex or not C_key_hex or not nonce_hex or not tag_hex or not K_priv_pem:
        st.warning(
            "Lengkapi minimal: C_text (hex), C_key (hex), nonce (hex), tag (hex), dan kunci privat RSA."
        )
    else:
        try:
            # Konversi dari hex ke bytes
            C_text = bytes.fromhex(C_text_hex.strip())
            C_key = bytes.fromhex(C_key_hex.strip())
            nonce = bytes.fromhex(nonce_hex.strip())
            tag = bytes.fromhex(tag_hex.strip())

            # ===========================================
            # Langkah 2: Dekripsi RSA untuk mendapatkan K_AES
            # K_AES = D_RSA(K_priv, C_key)
            # ===========================================
            priv_key = RSA.import_key(K_priv_pem)
            cipher_rsa = PKCS1_OAEP.new(priv_key, hashAlgo=SHA256)
            K_AES = cipher_rsa.decrypt(C_key)

            # ===========================================
            # Langkah 3: Dekripsi AES untuk mengembalikan plaintext
            # P' = D_AES(K_AES, C_text)
            # (untuk AES-GCM: butuh nonce dan tag)
            # ===========================================
            cipher_aes_dec = AES.new(K_AES, AES.MODE_GCM, nonce=nonce)
            P_bytes = cipher_aes_dec.decrypt_and_verify(C_text, tag)
            P_prime = P_bytes.decode("utf-8", errors="replace")

            st.markdown("## Hasil Simulasi Dekripsi")

            st.markdown("### Notasi Matematis")
            st.latex(r"K_{\text{AES}} = D_{\text{RSA}}(K_{\text{priv}}, C_{\text{key}})")
            st.latex(r"P' = D_{\text{AES}}(K_{\text{AES}}, C_{\text{text}})")

            st.markdown("### Kunci AES Hasil Dekripsi RSA")
            st.code(f"K_AES (128-bit, hex): {K_AES.hex()}", language="text")

            st.markdown("### Plaintext Hasil Dekripsi (P')")
            st.code(P_prime, language="text")

            # ===========================================
            # Langkah 4: Validasi hasil dekripsi (opsional)
            # Proses berhasil apabila P' = P
            # ===========================================
            if P_awal:
                if P_awal == P_prime:
                    st.success("Validasi Berhasil: P' = P (plaintext cocok dengan plaintext awal).")
                else:
                    st.error("Validasi Gagal: P' ≠ P (plaintext hasil dekripsi tidak sama dengan plaintext awal).")
            else:
                st.info(
                    "Untuk validasi P' = P, isi kolom 'Plaintext awal' dengan pesan asli "
                    "yang digunakan saat enkripsi."
                )

        except ValueError as e:
            st.error(f"Terjadi kesalahan saat dekripsi. Detail: {e}")
        except Exception as e:
            st.error(f"Terjadi error tak terduga: {e}")
