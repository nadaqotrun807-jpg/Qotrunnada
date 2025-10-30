import base64
import json
import time
from typing import Tuple, Dict

import streamlit as st
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes


# =========================
# Utilitas kriptografi
# =========================
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))


def derive_key(password: str, salt: bytes, iterations: int = 200_000, dk_len: int = 16) -> Tuple[bytes, float]:
    """
    Menurunkan kunci 128-bit dari password menggunakan PBKDF2-HMAC-SHA256.
    Mengembalikan (key, kdf_time_ms).
    """
    t0 = time.perf_counter()
    key = PBKDF2(password, salt, dkLen=dk_len, count=iterations)  # SHA1 default di PyCryptodome -> gunakan HMAC-SHA1
    # Catatan: Jika ingin SHA-256, gunakan hmac_hash_module dari Crypto.Hash import SHA256:
    # from Crypto.Hash import SHA256
    # key = PBKDF2(password, salt, dkLen=dk_len, count=iterations, hmac_hash_module=SHA256)
    t1 = time.perf_counter()
    return key, (t1 - t0) * 1000.0


def encrypt_gcm(plaintext: str, password: str, iterations: int = 200_000) -> Tuple[Dict, Dict]:
    """
    Enkripsi AES-128 GCM.
    Returns:
      payload_dict: {salt, nonce, tag, ciphertext} (Base64 string)
      timings_ms: {kdf_ms, enc_ms, total_ms}
    """
    if not isinstance(plaintext, str):
        raise ValueError("Plaintext harus string.")
    if not password:
        raise ValueError("Password tidak boleh kosong.")

    salt = get_random_bytes(16)  # diperlukan untuk KDF
    key, kdf_ms = derive_key(password, salt, iterations=iterations, dk_len=16)  # 16 byte = 128-bit

    nonce = get_random_bytes(12)  # 96-bit nonce direkomendasikan untuk GCM
    t0 = time.perf_counter()
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    t1 = time.perf_counter()
    enc_ms = (t1 - t0) * 1000.0

    payload = {
        "salt": b64e(salt),
        "nonce": b64e(nonce),
        "tag": b64e(tag),
        "ciphertext": b64e(ciphertext),
        "kdf_iterations": iterations,
        "kdf_len_bits": 128,
        "mode": "AES-128-GCM"
    }

    timings = {
        "kdf_ms": round(kdf_ms, 3),
        "enc_ms": round(enc_ms, 3),
        "total_ms": round(kdf_ms + enc_ms, 3),
    }
    return payload, timings


def decrypt_gcm(payload_json: str, password: str) -> Tuple[str, Dict]:
    """
    Dekripsi AES-128 GCM dari payload JSON (Base64).
    Returns:
      plaintext (str), timings_ms {kdf_ms, dec_ms, total_ms}
    """
    if not password:
        raise ValueError("Password tidak boleh kosong.")
    try:
        payload = json.loads(payload_json)
        salt = b64d(payload["salt"])
        nonce = b64d(payload["nonce"])
        tag = b64d(payload["tag"])
        ciphertext = b64d(payload["ciphertext"])
        iterations = int(payload.get("kdf_iterations", 200_000))
    except Exception as e:
        raise ValueError(f"Payload JSON tidak valid: {e}")

    key, kdf_ms = derive_key(password, salt, iterations=iterations, dk_len=16)

    t0 = time.perf_counter()
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext_bytes = cipher.decrypt_and_verify(ciphertext, tag)
    t1 = time.perf_counter()
    dec_ms = (t1 - t0) * 1000.0

    timings = {
        "kdf_ms": round(kdf_ms, 3),
        "dec_ms": round(dec_ms, 3),
        "total_ms": round(kdf_ms + dec_ms, 3),
    }
    return plaintext_bytes.decode("utf-8"), timings


# =========================
# UI Streamlit
# =========================
st.set_page_config(page_title="AES-128 GCM Demo + Timing", page_icon="🔐", layout="centered")
st.title("🔐 AES-128 (GCM) — Enkripsi Pesan + Pengukuran Waktu")
st.caption("Kunci 128-bit diturunkan dari password via PBKDF2. Waktu diukur dengan time.perf_counter().")

with st.sidebar:
    st.subheader("⚙️ Pengaturan")
    iterations = st.number_input("PBKDF2 Iterations (semakin besar semakin aman, tapi lebih lambat)", min_value=10_000, max_value=2_000_000, value=200_000, step=10_000)
    bench = st.checkbox("Uji rata-rata (benchmark) N kali")
    N = st.number_input("Jumlah pengulangan N", min_value=1, max_value=5000, value=30, step=1, disabled=not bench)
    st.markdown("---")
    st.info("Catatan metodologi:\n- **kdf_ms**: waktu derivasi kunci PBKDF2\n- **enc_ms/dec_ms**: waktu enkripsi/dekripsi murni AES-GCM\n- **total_ms**: kdf_ms + enc/dec_ms\nGunakan N>1 untuk rata-rata yang lebih stabil.")

tab_enc, tab_dec = st.tabs(["🔒 Enkripsi", "🔓 Dekripsi"])

with tab_enc:
    st.subheader("Enkripsi")
    plaintext = st.text_area("Masukkan pesan teks (plaintext)", height=150, placeholder="Contoh: Data rahasia yang ingin dienkripsi...")
    password = st.text_input("Password (akan diturunkan menjadi kunci 128-bit)", type="password")
    col1, col2 = st.columns(2)
    with col1:
        do_encrypt = st.button("Enkripsi Sekarang")
    with col2:
        st.write("")

    if do_encrypt:
        if not plaintext:
            st.warning("Masukkan plaintext terlebih dahulu.")
        elif not password:
            st.warning("Masukkan password terlebih dahulu.")
        else:
            # Single run or benchmark
            if bench and N > 1:
                kdf_list, enc_list, total_list = [], [], []
                last_payload = None
                for _ in range(N):
                    payload, timings = encrypt_gcm(plaintext, password, iterations=iterations)
                    last_payload = payload
                    kdf_list.append(timings["kdf_ms"])
                    enc_list.append(timings["enc_ms"])
                    total_list.append(timings["total_ms"])

                avg_kdf = sum(kdf_list) / len(kdf_list)
                avg_enc = sum(enc_list) / len(enc_list)
                avg_total = sum(total_list) / len(total_list)

                st.success("Enkripsi selesai (benchmark).")
                st.json(last_payload)
                st.write(f"📏 Panjang plaintext: **{len(plaintext.encode('utf-8'))} byte**")
                st.markdown(
                    f"""
                    **Rata-rata waktu (N={N}):**
                    - KDF (PBKDF2): **{avg_kdf:.3f} ms**
                    - Enkripsi AES-GCM: **{avg_enc:.3f} ms**
                    - Total: **{avg_total:.3f} ms**
                    """
                )
            else:
                payload, timings = encrypt_gcm(plaintext, password, iterations=iterations)
                st.success("Enkripsi selesai.")
                st.json(payload)
                st.write(f"📏 Panjang plaintext: **{len(plaintext.encode('utf-8'))} byte**")
                st.markdown(
                    f"""
                    **Waktu:**
                    - KDF (PBKDF2): **{timings['kdf_ms']:.3f} ms**  
                    - Enkripsi AES-GCM: **{timings['enc_ms']:.3f} ms**  
                    - Total: **{timings['total_ms']:.3f} ms**
                    """
                )
            st.info("Simpan JSON di atas (berisi salt/nonce/tag/ciphertext). Untuk dekripsi, tempel JSON dan gunakan password yang sama.")

with tab_dec:
    st.subheader("Dekripsi")
    payload_json = st.text_area("Tempel payload JSON hasil enkripsi", height=200, placeholder='{"salt":"...","nonce":"...","tag":"...","ciphertext":"...","kdf_iterations":200000,"kdf_len_bits":128,"mode":"AES-128-GCM"}')
    password_dec = st.text_input("Password yang sama (untuk menghasilkan kunci)", type="password", key="pwd_dec")
    col1, col2 = st.columns(2)
    with col1:
        do_decrypt = st.button("Dekripsi Sekarang")
    with col2:
        st.write("")

    if do_decrypt:
        try:
            plaintext_out, timings = decrypt_gcm(payload_json, password_dec)
            st.success("Dekripsi berhasil dan tag tervalidasi ✅")
            st.code(plaintext_out, language="text")
            st.markdown(
                f"""
                **Waktu:**
                - KDF (PBKDF2): **{timings['kdf_ms']:.3f} ms**  
                - Dekripsi AES-GCM: **{timings['dec_ms']:.3f} ms**  
                - Total: **{timings['total_ms']:.3f} ms**
                """
            )
            st.write(f"📏 Panjang plaintext: **{len(plaintext_out.encode('utf-8'))} byte**")
        except Exception as e:
            st.error(f"Gagal dekripsi/verifikasi tag. Periksa password dan payload JSON.\nDetail: {e}")
