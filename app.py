import base64
import os
import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ---------- Helper ----------
def b64encode(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64decode(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def normalize_key(key_input: str, key_format: str) -> bytes:
    """
    Menghasilkan key 16-byte (128-bit) sesuai pilihan format.
    - 'Teks 16 karakter'   -> gunakan langsung, harus panjang 16
    - 'Hex 32 digit'       -> parse hex jadi 16 byte
    - 'Passphrase (KDF)'   -> derive 16 byte dari passphrase (PBKDF2)
    """
    if key_format == "Teks 16 karakter":
        if len(key_input) != 16:
            raise ValueError("Kunci teks harus tepat 16 karakter untuk AES-128.")
        return key_input.encode("utf-8")

    elif key_format == "Hex 32 digit":
        key_input = key_input.strip().lower().replace("0x", "")
        if len(key_input) != 32 or any(c not in "0123456789abcdef" for c in key_input):
            raise ValueError("Kunci hex harus tepat 32 digit hex (128-bit).")
        return bytes.fromhex(key_input)

    elif key_format == "Passphrase (KDF)":
        # Derivasi sederhana via PBKDF2-HMAC-SHA256
        from Crypto.Protocol.KDF import PBKDF2
        from Crypto.Hash import SHA256
        salt = b"AES-128-GCM-EDU"  # salt statis untuk demo; di produksi gunakan salt acak & simpan
        return PBKDF2(key_input, salt, dkLen=16, count=200_000, hmac_hash_module=SHA256)

    else:
        raise ValueError("Format kunci tidak dikenal.")

def aes_gcm_encrypt(plaintext: str, key: bytes) -> dict:
    """
    Enkripsi AES-128-GCM.
    Return dict dengan base64 untuk nonce, ciphertext, tag dan paket gabungan.
    Paket gabungan = base64( nonce || tag || ciphertext )
    Urutan disepakati agar mudah didekripsi.
    """
    nonce = get_random_bytes(12)  # rekomendasi GCM: 96-bit nonce
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    packed = nonce + tag + ciphertext
    return {
        "nonce_b64": b64encode(nonce),
        "tag_b64": b64encode(tag),
        "ciphertext_b64": b64encode(ciphertext),
        "package_b64": b64encode(packed),
    }

def aes_gcm_decrypt(package_b64: str, key: bytes) -> str:
    """
    Dekripsi paket gabungan base64( nonce || tag || ciphertext ).
    """
    packed = b64decode(package_b64)
    if len(packed) < 12 + 16 + 1:
        raise ValueError("Paket tidak valid atau terlalu pendek.")
    nonce = packed[:12]
    tag = packed[12:28]
    ciphertext = packed[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode("utf-8")

# ---------- UI ----------
st.set_page_config(page_title="AES-128 GCM • Pesan Teks", page_icon="🔐", layout="centered")

st.title("🔐 AES-128 (GCM) — Pesan Teks")
st.write(
    "Aplikasi ini mengenkripsi **pesan teks** dengan **AES-128** dalam mode **GCM** "
    "(memberikan kerahasiaan + integritas melalui *authentication tag*)."
)

with st.sidebar:
    st.header("Pengaturan Kunci (128-bit)")
    key_format = st.selectbox(
        "Format kunci",
        ["Teks 16 karakter", "Hex 32 digit", "Passphrase (KDF)"],
        index=0,
        help="Pilih cara memasukkan kunci. Untuk demo termudah, gunakan 'Teks 16 karakter'.",
    )

    if key_format == "Teks 16 karakter":
        key_input = st.text_input(
            "Kunci (16 karakter)",
            value="ABCDEFGHIJKLMNOP",
            help="Harus tepat 16 karakter (contoh diisi untuk demo).",
            type="password",
        )
    elif key_format == "Hex 32 digit":
        key_input = st.text_input(
            "Kunci (32 digit hex)",
            value="00112233445566778899aabbccddeeff",
            help="Contoh: 00112233445566778899aabbccddeeff",
        )
    else:  # Passphrase (KDF)
        key_input = st.text_input(
            "Passphrase",
            value="passphrase-demo-aman",
            help="Akan diturunkan menjadi 128-bit via PBKDF2-HMAC-SHA256.",
            type="password",
        )

    # Validasi/derivasi kunci
    key_bytes = None
    key_error = None
    try:
        key_bytes = normalize_key(key_input, key_format)
    except Exception as e:
        key_error = str(e)

tab_enc, tab_dec = st.tabs(["🔒 Enkripsi", "🔓 Dekripsi"])

with tab_enc:
    st.subheader("Enkripsi Pesan")
    plaintext = st.text_area(
        "Masukkan pesan (plaintext)",
        placeholder="Tulis pesan teks di sini...",
        height=160,
    )
    if st.button("Enkripsi", type="primary", key="btn_encrypt"):
        if key_error:
            st.error(f"Kesalahan kunci: {key_error}")
        elif not plaintext:
            st.warning("Isi pesan belum diisi.")
        else:
            try:
                result = aes_gcm_encrypt(plaintext, key_bytes)
                st.success("Berhasil dienkripsi dengan AES-128-GCM.")
                st.code(result["package_b64"], language="text")
                with st.expander("Detail komponen (base64)"):
                    st.write("Nonce (12 byte):")
                    st.code(result["nonce_b64"], language="text")
                    st.write("Authentication Tag (16 byte):")
                    st.code(result["tag_b64"], language="text")
                    st.write("Ciphertext:")
                    st.code(result["ciphertext_b64"], language="text")

                st.download_button(
                    "⬇️ Unduh Paket Cipher (base64)",
                    data=result["package_b64"],
                    file_name="cipher_aes128_gcm.txt",
                    mime="text/plain",
                    key="dl_cipher",
                )
                st.info(
                    "Catatan: Simpan **kunci** dan **paket base64** ini. "
                    "Dekripsi membutuhkan keduanya."
                )
            except Exception as e:
                st.error(f"Gagal enkripsi: {e}")

with tab_dec:
    st.subheader("Dekripsi Paket")
    st.write(
        "Tempel **paket base64** hasil enkripsi (format: base64(nonce||tag||ciphertext))."
    )
    package_b64 = st.text_area(
        "Paket Cipher (base64)",
        placeholder="Tempel paket base64 di sini untuk didekripsi...",
        height=160,
        key="pkg_input",
    )
    if st.button("Dekripsi", key="btn_decrypt"):
        if key_error:
            st.error(f"Kesalahan kunci: {key_error}")
        elif not package_b64.strip():
            st.warning("Paket base64 belum diisi.")
        else:
            try:
                plaintext = aes_gcm_decrypt(package_b64.strip(), key_bytes)
                st.success("Berhasil didekripsi.")
                st.text_area("Hasil Plaintext:", value=plaintext, height=160)
            except Exception as e:
                st.error(f"Gagal dekripsi: {e}")

st.caption(
    "Mode GCM menyediakan *authenticated encryption* (AEAD). "
    "Nonce diacak setiap enkripsi. Panjang kunci = 128-bit sesuai permintaan."
)
