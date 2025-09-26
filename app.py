import base64
import io
import os
from typing import Tuple

import streamlit as st
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


# ──────────────────────────────────────────────────────────────────────────────
# UTIL: Konversi & PKCS7
# ──────────────────────────────────────────────────────────────────────────────
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

# ──────────────────────────────────────────────────────────────────────────────
# AES-GCM (PyCryptodome)
# ──────────────────────────────────────────────────────────────────────────────
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

def generate_key(n_bits: int = 128) -> bytes:
    if n_bits not in (128, 192, 256):
        raise ValueError("Panjang kunci harus 128, 192, atau 256 bit.")
    return get_random_bytes(n_bits // 8)

def generate_nonce() -> bytes:
    # 12 byte adalah ukuran nonce yang direkomendasikan untuk GCM
    return get_random_bytes(12)

def encrypt_aes_gcm(plaintext: bytes, key: bytes, aad: bytes = b"") -> Tuple[bytes, bytes, bytes]:
    """
    Return: (nonce, ciphertext, tag)
    """
    nonce = generate_nonce()
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce, ciphertext, tag

def decrypt_aes_gcm(nonce: bytes, ciphertext: bytes, tag: bytes, key: bytes, aad: bytes = b"") -> bytes:
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, tag)

# ──────────────────────────────────────────────────────────────────────────────
# STREAMLIT APP
# ──────────────────────────────────────────────────────────────────────────────
st.set_page_config(page_title="AES-GCM Demo", page_icon="🛡️", layout="centered")

st.title("🔐 AES (GCM) – Enkripsi & Dekripsi")
st.caption("Aman (confidentiality + integrity) menggunakan PyCryptodome. UI menghindari konflik key Streamlit.")

with st.expander("ℹ️ Panduan singkat", expanded=False):
    st.markdown(
        """
- **Modus:** AES-GCM (direkomendasikan) — menghasilkan `ciphertext` + `tag` untuk verifikasi integritas.  
- **I/O format:** tampil sebagai **Base64** agar mudah copy–paste/unduh.  
- **Kunci:** bisa **buat otomatis** atau **input manual** dalam bentuk **hex**.  
- **Atribut tambahan (AAD):** opsional; jika diisi saat enkripsi, **wajib** sama saat dekripsi.
- **Catatan error ‘duplicate key’:** semua komponen diberi `key` **statik & unik**, bukan dinamis dari data/nonce.
        """
    )

st.subheader("1) Konfigurasi Kunci", anchor="config")

col1, col2 = st.columns(2)
with col1:
    key_len_bits = st.radio(
        "Panjang kunci",
        options=[128, 192, 256],
        index=0,
        horizontal=True,
        key="key_len_bits_radio",
        help="Pilih ukuran keamanan. 128-bit sudah kuat untuk banyak use case."
    )

with col2:
    key_mode = st.radio(
        "Sumber kunci",
        options=["Generate otomatis", "Masukkan manual (hex)"],
        index=0,
        horizontal=False,
        key="key_mode_radio"
    )

if "app_key_bytes" not in st.session_state:
    st.session_state.app_key_bytes = generate_key(key_len_bits)

if key_mode == "Generate otomatis":
    if st.button("🔁 Generate kunci baru", key="btn_gen_key"):
        st.session_state.app_key_bytes = generate_key(key_len_bits)
    st.text_input(
        "Kunci (hex) – readonly",
        value=st.session_state.app_key_bytes.hex(),
        key="key_hex_display",
        help="Ini adalah kunci yang sedang dipakai.",
        disabled=True
    )
else:
    key_hex_input = st.text_input(
        "Masukkan kunci (hex)",
        value=st.session_state.app_key_bytes.hex(),
        key="key_hex_input",
        help=f"Panjang harus sesuai: {key_len_bits//8} byte → {key_len_bits//4} digit hex."
    )
    apply_key = st.button("✅ Pakai kunci ini", key="btn_apply_key")
    if apply_key:
        try:
            kb = bytes.fromhex(key_hex_input.strip())
            if len(kb) != (key_len_bits // 8):
                st.error(f"Panjang kunci tidak sesuai. Diperlukan {key_len_bits//8} byte.")
            else:
                st.session_state.app_key_bytes = kb
                st.success("Kunci diperbarui.")
        except ValueError:
            st.error("Format hex tidak valid.")

aad_text = st.text_input(
    "AAD (opsional, akan dilindungi integritas – Base64 saat tampil)",
    value="",
    key="aad_text_input",
    help="Jika digunakan, AAD harus identik saat enkripsi & dekripsi."
)

st.markdown("---")
tab_enc, tab_dec = st.tabs(["🔒 Enkripsi", "🔓 Dekripsi"])

# ──────────────────────────────────────────────────────────────────────────────
# ENKRIPSI
# ──────────────────────────────────────────────────────────────────────────────
with tab_enc:
    st.subheader("Input Data untuk Enkripsi")

    src = st.radio(
        "Sumber data",
        options=["Ketik teks", "Unggah file"],
        index=0,
        key="enc_source_radio",
        horizontal=True
    )

    plaintext_bytes = b""
    filename_hint = "encrypted.bin"
    if src == "Ketik teks":
        text = st.text_area(
            "Plaintext (teks UTF-8)",
            height=150,
            key="enc_text_area",
            placeholder="Tulis pesan rahasia di sini…"
        )
        if text:
            plaintext_bytes = text.encode("utf-8")
            filename_hint = "encrypted.txt.bin"
    else:
        up = st.file_uploader(
            "Pilih file untuk dienkripsi",
            type=None,
            key="enc_file_uploader"
        )
        if up is not None:
            plaintext_bytes = up.read()
            filename_hint = os.path.splitext(up.name)[0] + ".enc"

    do_encrypt = st.button("🚀 Enkripsi dengan AES-GCM", key="btn_encrypt_now")
    if do_encrypt:
        if not plaintext_bytes:
            st.warning("Mohon isi teks atau unggah file terlebih dahulu.")
        else:
            aad_bytes = aad_text.encode("utf-8") if aad_text else b""
            key = st.session_state.app_key_bytes
            nonce, ct, tag = encrypt_aes_gcm(plaintext_bytes, key, aad=aad_bytes)

            st.success("Enkripsi berhasil.")
            st.code(f"Nonce (Base64): {b64e(nonce)}", language="text")
            st.code(f"Tag   (Base64): {b64e(tag)}", language="text")
            st.code(f"Ciphertext (Base64): {b64e(ct)}", language="text")

            # Paket gabungan (nonce || tag || ciphertext) — praktis untuk simpan/unduh
            packaged = b"".join([nonce, tag, ct])
            st.download_button(
                label="⬇️ Unduh paket (nonce||tag||ciphertext)",
                data=packaged,
                file_name=filename_hint,
                mime="application/octet-stream",
                key="dl_enc_package_btn"
            )

            # Alternatif: simpan tiga elemen dalam file teks (Base64)
            text_bundle = (
                f"nonce_b64={b64e(nonce)}\n"
                f"tag_b64={b64e(tag)}\n"
                f"ciphertext_b64={b64e(ct)}\n"
            )
            st.download_button(
                label="⬇️ Unduh hasil (teks Base64)",
                data=text_bundle.encode("utf-8"),
                file_name="aes_gcm_result.txt",
                mime="text/plain",
                key="dl_enc_textbundle_btn"
            )

# ──────────────────────────────────────────────────────────────────────────────
# DEKRIPSI
# ──────────────────────────────────────────────────────────────────────────────
with tab_dec:
    st.subheader("Pilih Format Input Dekripsi")

    dec_mode = st.radio(
        "Format input",
        options=["Masukkan Base64 masing-masing (Nonce/Tag/Ciphertext)", "Unggah paket biner (nonce||tag||ciphertext)"],
        index=0,
        horizontal=False,
        key="dec_mode_radio"
    )

    nonce_b64 = tag_b64 = ct_b64 = ""
    packed_bytes = None

    if dec_mode.startswith("Masukkan"):
        nonce_b64 = st.text_input("Nonce (Base64)", key="dec_nonce_b64")
        tag_b64 = st.text_input("Tag (Base64)", key="dec_tag_b64")
        ct_b64 = st.text_area("Ciphertext (Base64)", key="dec_ct_b64", height=150)
    else:
        up_pack = st.file_uploader(
            "Unggah file paket biner (nonce||tag||ciphertext)",
            type=None,
            key="dec_pack_uploader"
        )
        if up_pack is not None:
            packed_bytes = up_pack.read()

    do_decrypt = st.button("🧩 Dekripsi sekarang", key="btn_decrypt_now")
    if do_decrypt:
        key = st.session_state.app_key_bytes
        aad_bytes = aad_text.encode("utf-8") if aad_text else b""

        try:
            if packed_bytes:
                # Paket gabungan: 12 byte nonce, 16 byte tag (default GCM), sisanya ciphertext
                if len(packed_bytes) < 12 + 16:
                    st.error("Paket terlalu pendek. Pastikan format: nonce(12B)||tag(16B)||ciphertext.")
                else:
                    nonce = packed_bytes[:12]
                    tag = packed_bytes[12:28]
                    ct = packed_bytes[28:]
                    pt = decrypt_aes_gcm(nonce, ct, tag, key, aad=aad_bytes)
            else:
                if not (nonce_b64 and tag_b64 and ct_b64):
                    st.error("Mohon isi Nonce/Tag/Ciphertext (Base64) lengkap atau unggah paket.")
                    st.stop()
                nonce = b64d(nonce_b64.strip())
                tag = b64d(tag_b64.strip())
                ct = b64d(ct_b64.strip())
                pt = decrypt_aes_gcm(nonce, ct, tag, key, aad=aad_bytes)

            # Tampilkan sebagai teks (jika UTF-8) + tombol unduh
            try:
                as_text = pt.decode("utf-8")
                st.success("Dekripsi sukses. Menampilkan hasil sebagai teks (UTF-8).")
                st.text_area("Plaintext (UTF-8)", value=as_text, height=150, key="dec_plaintext_display")
            except UnicodeDecodeError:
                st.success("Dekripsi sukses. Hasil adalah biner (bukan teks UTF-8).")

            st.download_button(
                label="⬇️ Unduh plaintext",
                data=pt,
                file_name="decrypted_output",
                mime="application/octet-stream",
                key="dl_plain_btn"
            )
        except ValueError as e:
            # Kesalahan tipikal: tag tidak cocok (kunci/nonce/tag/AAD salah)
            st.error(f"Gagal dekripsi: {e}. Pastikan kunci, nonce, tag, dan AAD sesuai.")
        except Exception as e:
            st.error(f"Terjadi error tak terduga: {e}")
