# app.py — Hybrid RSA–AES (AES-GCM + RSA-OAEP) dengan timing
import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from time import perf_counter
import json

st.set_page_config(page_title="Hybrid RSA–AES", page_icon="🔐", layout="wide")
st.title("🔐 Hybrid RSA–AES (AES-GCM + RSA-OAEP) — Encrypt & Decrypt + Timing")
st.caption("AES-GCM mengenkripsi plaintext; RSA-OAEP membungkus kunci AES. Waktu diukur dengan time.perf_counter().")

# ---------------- Sidebar (opsi uji) ----------------
rsa_bits = st.sidebar.selectbox("RSA Key Size", [2048, 3072, 4096], index=1)
aes_bits = st.sidebar.selectbox("AES Key Length (bit)", [128, 192, 256], index=0)
reps     = st.sidebar.slider("Repetitions (avg timing)", 1, 20, 5)
st.sidebar.caption("Ulangan membantu menstabilkan rata-rata waktu.")

# ---------------- State init ----------------
if "rsa_priv" not in st.session_state:
    st.session_state["rsa_priv"] = None
    st.session_state["rsa_pub"] = None
if "enc_blob" not in st.session_state:
    st.session_state["enc_blob"] = None

# ---------------- 1) Keypair RSA ----------------
st.subheader("1) Generate / Siapkan Kunci RSA")
c1, c2 = st.columns(2)
with c1:
    if st.button("Generate RSA Keypair"):
        key = RSA.generate(rsa_bits)
        st.session_state["rsa_priv"] = key
        st.session_state["rsa_pub"]  = key.public_key()
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
    st.info("Klik **Generate RSA Keypair** terlebih dahulu.")
    st.stop()

# ---------------- 2) ENKRIPSI HYBRID ----------------
st.subheader("2) Enkripsi Hybrid (AES-GCM untuk plaintext + RSA-OAEP untuk kunci)")
plaintext = st.text_area("Plaintext:", "Pengujian hybrid RSA–AES untuk skripsi.")

if st.button("🔒 Enkripsi & Ukur Waktu"):
    if not plaintext:
        st.error("Plaintext masih kosong.")
    else:
        # AES-GCM
        aes_len = aes_bits // 8
        aes_key = get_random_bytes(aes_len)

        aes_times = []
        rsa_times = []
        # simpan artifacts dari run terakhir
        nonce = tag = ct = enc_aes_key = None

        for _ in range(reps):
            t0 = perf_counter()
            aes = AES.new(aes_key, AES.MODE_GCM)   # nonce otomatis
            ct, tag = aes.encrypt_and_digest(plaintext.encode("utf-8"))
            nonce = aes.nonce
            t1 = perf_counter()
            aes_times.append(t1 - t0)

            # RSA-OAEP untuk membungkus kunci AES
            t2 = perf_counter()
            rsa_enc = PKCS1_OAEP.new(st.session_state["rsa_pub"])
            enc_aes_key = rsa_enc.encrypt(aes_key)
            t3 = perf_counter()
            rsa_times.append(t3 - t2)

        avg_aes_enc = sum(aes_times) / len(aes_times)
        avg_rsa_enc = sum(rsa_times) / len(rsa_times)
        avg_total   = avg_aes_enc + avg_rsa_enc

        st.success("Enkripsi selesai.")
        c1, c2, c3 = st.columns(3)
        c1.metric("AES Encrypt (avg)",  f"{avg_aes_enc:.6f} s")
        c2.metric("RSA Encrypt (avg)",  f"{avg_rsa_enc:.6f} s")
        c3.metric("Total Encrypt (≈)",  f"{avg_total:.6f} s")

        # simpan payload untuk dekripsi
        enc_blob = {
            "rsa_bits": rsa_bits,
            "aes_bits": aes_bits,
            "ciphertext_hex": ct.hex(),
            "nonce_hex": nonce.hex(),
            "tag_hex": tag.hex(),
            "enc_aes_key_hex": enc_aes_key.hex(),
        }
        st.session_state["enc_blob"] = enc_blob

        st.code(json.dumps(enc_blob, indent=2), language="json")
        st.download_button("Unduh Payload Enkripsi (.json)",
                           data=json.dumps(enc_blob, indent=2).encode("utf-8"),
                           file_name="encrypted_payload.json")

# ---------------- 3) DEKRIPSI HYBRID ----------------
st.subheader("3) Dekripsi Hybrid (RSA-OAEP unwrap + AES-GCM verify)")
up = st.file_uploader("Unggah Payload Enkripsi (.json) atau gunakan payload dari langkah (2)", type=["json"])

if st.button("🔓 Dekripsi & Ukur Waktu"):
    # Ambil payload
    if up is not None:
        import json as _json
        enc_blob = _json.load(up)
    else:
        enc_blob = st.session_state.get("enc_blob")

    if not enc_blob:
        st.error("Tidak ada payload enkripsi. Jalankan enkripsi dulu atau unggah file JSON.")
    elif not st.session_state["rsa_priv"]:
        st.error("Kunci privat RSA belum tersedia.")
    else:
        try:
            ct   = bytes.fromhex(enc_blob["ciphertext_hex"])
            nonce= bytes.fromhex(enc_blob["nonce_hex"])
            tag  = bytes.fromhex(enc_blob["tag_hex"])
            enc_aes_key = bytes.fromhex(enc_blob["enc_aes_key_hex"])
        except Exception as e:
            st.error(f"Format payload tidak valid: {e}")
            st.stop()

        # RSA-OAEP: unwrap AES key
        t0 = perf_counter()
        rsa_dec = PKCS1_OAEP.new(st.session_state["rsa_priv"])
        aes_key = rsa_dec.decrypt(enc_aes_key)
        t1 = perf_counter()
        t_rsa_dec = t1 - t0

        # AES-GCM: decrypt & verify
        t2 = perf_counter()
        aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        plaintext_out = aes.decrypt_and_verify(ct, tag)
        t3 = perf_counter()
        t_aes_dec = t3 - t2
        t_total   = (t3 - t0)

        c1, c2, c3 = st.columns(3)
        c1.metric("RSA Decrypt (unwrap)", f"{t_rsa_dec:.6f} s")
        c2.metric("AES Decrypt",          f"{t_aes_dec:.6f} s")
        c3.metric("Total Decrypt",        f"{t_total:.6f} s")

        try:
            st.text_area("Plaintext hasil dekripsi:", plaintext_out.decode("utf-8"), height=120)
        except UnicodeDecodeError:
            st.code(plaintext_out, language="text")
        st.success("Dekripsi berhasil & tag terverifikasi.")
