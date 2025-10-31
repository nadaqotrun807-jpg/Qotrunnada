# app.py — RSA-OAEP membungkus kunci AES-128 + timing (dengan UI)
import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from time import perf_counter

st.set_page_config(page_title="Hybrid RSA–AES", page_icon="🔐", layout="wide")
st.title("🔐 Hybrid RSA–AES (Key Wrap + AES-GCM) + Timing")

# Sidebar: pengaturan
colsz = st.sidebar.container()
rsa_bits = colsz.selectbox("RSA Key Size", [2048, 3072, 4096], index=1)
reps     = colsz.slider("Repetitions (avg timing)", 1, 20, 5)
st.sidebar.caption("Gunakan pengulangan untuk rata-rata waktu yang stabil.")

# State kunci
if "rsa_priv" not in st.session_state:
    st.session_state["rsa_priv"] = None
    st.session_state["rsa_pub"] = None

st.subheader("1) Keypair RSA")
c1, c2 = st.columns(2)
with c1:
    if st.button("Generate Keypair"):
        key = RSA.generate(rsa_bits)
        st.session_state["rsa_priv"] = key
        st.session_state["rsa_pub"] = key.public_key()
        st.success(f"RSA {rsa_bits}-bit dibuat.")
with c2:
    if st.session_state["rsa_pub"]:
        st.download_button("Unduh Public Key (PEM)",
                           st.session_state["rsa_pub"].export_key(),
                           file_name=f"rsa_{rsa_bits}_pub.pem")
        st.download_button("Unduh Private Key (PEM)",
                           st.session_state["rsa_priv"].export_key(),
                           file_name=f"rsa_{rsa_bits}_priv.pem")

if not st.session_state["rsa_pub"]:
    st.info("Klik **Generate Keypair** dulu.")
    st.stop()

st.subheader("2) Enkripsi Kunci AES-128 (RSA-OAEP) + Timing")
if st.button("🔒 Encrypt AES Key & Measure"):
    aes_key = get_random_bytes(16)  # 128-bit
    rsa_enc = PKCS1_OAEP.new(st.session_state["rsa_pub"])

    times = []
    enc_aes_key = None
    for _ in range(reps):
        t0 = perf_counter()
        enc_aes_key = rsa_enc.encrypt(aes_key)
        t1 = perf_counter()
        times.append(t1 - t0)
    avg_enc = sum(times) / len(times)

    st.success("RSA encrypt selesai.")
    st.code(
        f"AES key (hex): {aes_key.hex()}\n"
        f"enc_aes_key len: {len(enc_aes_key)} byte",
        language="text"
    )
    st.metric("Avg RSA Encrypt (key wrap)", f"{avg_enc:.6f} s")
    st.session_state["aes_key"] = aes_key
    st.session_state["enc_aes_key"] = enc_aes_key

st.subheader("3) Dekripsi Kunci AES (RSA-OAEP) + Timing")
if st.button("🔓 Decrypt & Measure"):
    if "enc_aes_key" not in st.session_state:
        st.error("Belum ada hasil enkripsi kunci. Jalankan langkah (2) dulu.")
    else:
        rsa_dec = PKCS1_OAEP.new(st.session_state["rsa_priv"])
        times = []
        dec_aes_key = None
        for _ in range(reps):
            t0 = perf_counter()
            dec_aes_key = rsa_dec.decrypt(st.session_state["enc_aes_key"])
            t1 = perf_counter()
            times.append(t1 - t0)
        avg_dec = sum(times) / len(times)
        ok = (dec_aes_key == st.session_state["aes_key"])
        st.success(f"Dekripsi {'OK' if ok else 'GAGAL'}")
        st.metric("Avg RSA Decrypt (key unwrap)", f"{avg_dec:.6f} s")

st.subheader("4) Enkripsi Plaintext (AES-GCM) + Timing")
msg = st.text_area("Plaintext:", "Pengujian hybrid RSA–AES untuk skripsi.")
if st.button("🧪 AES-GCM Encrypt & Measure"):
    aes_key = st.session_state.get("aes_key") or get_random_bytes(16)
    t0 = perf_counter()
    aes = AES.new(aes_key, AES.MODE_GCM)
    ct, tag = aes.encrypt_and_digest(msg.encode("utf-8"))
    nonce = aes.nonce
    t1 = perf_counter()
    st.success("AES-GCM encrypt selesai.")
    st.metric("AES Encrypt (single run)", f"{(t1 - t0):.6f} s")
    st.code(
        f"nonce: {nonce.hex()}\ntag  : {tag.hex()}\nct   : {ct.hex()[:64]}...",
        language="text"
    )
