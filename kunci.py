# app.py — Simulasi Enkripsi Kunci AES (128-bit) dengan RSA-OAEP + Timing
import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from time import perf_counter

st.set_page_config(page_title="RSA–AES Key Wrap", page_icon="🔐", layout="centered")
st.title("🔐 Simulasi Enkripsi Kunci AES-128 dengan RSA-OAEP")
st.caption("Membungkus kunci AES (128-bit) menggunakan kunci publik RSA, lalu verifikasi dengan kunci privat. Waktu diukur dengan time.perf_counter().")

# Sidebar: pengaturan
rsa_bits = st.sidebar.selectbox("RSA Key Size", [2048, 3072, 4096], index=1)
reps = st.sidebar.slider("Jumlah Pengulangan (rata-rata waktu)", 1, 20, 5)
st.sidebar.caption("Lebih banyak pengulangan → rata-rata lebih stabil.")

# Bagian 1: Generate RSA keypair
st.subheader("1) Generate Keypair RSA")
if "rsa_priv" not in st.session_state:
    st.session_state["rsa_priv"] = None
    st.session_state["rsa_pub"] = None

col1, col2 = st.columns(2)
with col1:
    if st.button("Generate Keypair"):
        key = RSA.generate(rsa_bits)
        st.session_state["rsa_priv"] = key
        st.session_state["rsa_pub"] = key.public_key()
        st.success(f"RSA {rsa_bits}-bit berhasil dibuat.")
with col2:
    if st.session_state["rsa_pub"] is not None:
        pub_pem = st.session_state["rsa_pub"].export_key()
        priv_pem = st.session_state["rsa_priv"].export_key()
        st.download_button("Unduh Public Key (PEM)", pub_pem, file_name=f"rsa_{rsa_bits}_pub.pem")
        st.download_button("Unduh Private Key (PEM)", priv_pem, file_name=f"rsa_{rsa_bits}_priv.pem")

if st.session_state["rsa_pub"] is None:
    st.info("Klik **Generate Keypair** dulu untuk membuat kunci RSA.")
    st.stop()

# Bagian 2: Enkripsi kunci AES (key wrapping)
st.subheader("2) Enkripsi Kunci AES-128 (Key Wrapping) + Timing")
st.write("Menyiapkan kunci AES 128-bit acak, lalu dienkripsi dengan RSA-OAEP (public key).")

if st.button("🔒 Enkripsi Kunci AES & Ukur Waktu"):
    aes_key = get_random_bytes(16)  # 16 byte = 128-bit
    rsa_enc = PKCS1_OAEP.new(st.session_state["rsa_pub"])

    times = []
    enc_aes_key = None
    for _ in range(reps):
        t0 = perf_counter()
        enc_aes_key = rsa_enc.encrypt(aes_key)
        t1 = perf_counter()
        times.append(t1 - t0)

    avg_enc = sum(times) / len(times)

    st.success("Enkripsi kunci AES selesai.")
    st.code(
        f"AES key (hex): {aes_key.hex()}\n"
        f"enc_aes_key length: {len(enc_aes_key)} byte (≈ ukuran modulus RSA dalam byte)",
        language="text"
    )
    st.metric("Rata-rata Waktu RSA Encrypt (kunci AES)", f"{avg_enc:.6f} s")
    st.session_state["last_aes_key"] = aes_key
    st.session_state["last_enc_aes_key"] = enc_aes_key

# Bagian 3: Dekripsi kunci AES (verifikasi)
st.subheader("3) Dekripsi Kunci AES (Verifikasi) + Timing")
if st.button("🔓 Dekripsi & Ukur Waktu"):
    if "last_enc_aes_key" not in st.session_state or st.session_state["last_enc_aes_key"] is None:
        st.error("Belum ada hasil enkripsi kunci AES. Jalankan langkah (2) dulu.")
    else:
        rsa_dec = PKCS1_OAEP.new(st.session_state["rsa_priv"])
        times_d = []
        dec_aes_key = None
        for _ in range(reps):
            t2 = perf_counter()
            dec_aes_key = rsa_dec.decrypt(st.session_state["last_enc_aes_key"])
            t3 = perf_counter()
            times_d.append(t3 - t2)
        avg_dec = sum(times_d) / len(times_d)

        ok = (dec_aes_key == st.session_state["last_aes_key"])
        if ok:
            st.success("Dekripsi OK ✔ — kunci cocok dengan aslinya.")
        else:
            st.error("Dekripsi GAGAL ❌ — kunci tidak cocok.")

        st.code(
            f"Decrypted AES key (hex): {dec_aes_key.hex()}",
            language="text"
        )
        st.metric("Rata-rata Waktu RSA Decrypt (kunci AES)", f"{avg_dec:.6f} s")
