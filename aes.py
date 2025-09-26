import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding
import base64
from ast import literal_eval

# =========================
# Util umum
# =========================
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def to_bytes_from_hex_or_b64_or_utf8(s: str) -> bytes:
    s = s.strip()
    # hex?
    try:
        return bytes.fromhex(s)
    except Exception:
        pass
    # base64?
    try:
        return b64d(s)
    except Exception:
        pass
    # utf-8
    return s.encode("utf-8")

def random_key(bits: int) -> bytes:
    assert bits in (128, 192, 256)
    return get_random_bytes(bits // 8)

def generate_iv(mode: str) -> bytes:
    if mode == "CBC":
        return get_random_bytes(16)   # IV 16B
    if mode == "CTR":
        return get_random_bytes(16)   # nonce 8–16B, gunakan 16B
    if mode == "GCM":
        return get_random_bytes(12)   # nonce 12B direkomendasikan
    raise ValueError("Mode tidak dikenal")

def build_cipher(mode: str, key: bytes, iv_or_nonce: bytes, aad: bytes | None = None):
    if mode == "CBC":
        return AES.new(key, AES.MODE_CBC, iv=iv_or_nonce)
    if mode == "CTR":
        return AES.new(key, AES.MODE_CTR, nonce=iv_or_nonce)
    if mode == "GCM":
        c = AES.new(key, AES.MODE_GCM, nonce=iv_or_nonce)
        if aad:
            c.update(aad)
        return c
    raise ValueError("Mode tidak dikenal")

def pkcs7_pad(b: bytes) -> bytes:
    return Padding.pad(b, 16, style="pkcs7")

def pkcs7_unpad(b: bytes) -> bytes:
    return Padding.unpad(b, 16, style="pkcs7")

# =========================
# UI helpers (tanpa bentrok key)
# =========================
def show_bytes(label: str, b: bytes, out_encoding: str):
    val = b64e(b) if out_encoding == "base64" else b.hex()
    st.markdown(f"**{label}:**")
    st.code(val)

def parse_iv_nonce(mode: str, user_text: str | None):
    if user_text and user_text.strip():
        raw = to_bytes_from_hex_or_b64_or_utf8(user_text)
        if mode == "CBC" and len(raw) != 16:
            st.error("IV CBC harus 16 byte.")
            return None
        if mode == "CTR" and not (8 <= len(raw) <= 16):
            st.error("Nonce CTR direkomendasikan 8–16 byte.")
            return None
        if mode == "GCM" and len(raw) != 12:
            st.error("Nonce GCM yang direkomendasikan adalah 12 byte.")
            return None
        return raw
    return generate_iv(mode)

def parse_aad(aad_text: str) -> bytes | None:
    if not aad_text.strip():
        return None
    return to_bytes_from_hex_or_b64_or_utf8(aad_text)

# =========================
# Aplikasi
# =========================
st.set_page_config(page_title="AES Streamlit", page_icon="🔐", layout="centered")
st.title("🔐 AES Encrypt/Decrypt (CBC / CTR / GCM)")
st.caption("Mode disarankan: **GCM** (authenticated encryption). Jangan pernah reuse Nonce/IV pada key yang sama.")

with st.sidebar:
    st.header("⚙️ Pengaturan")
    mode = st.selectbox("Mode AES", ["GCM", "CBC", "CTR"])
    key_bits = st.selectbox("Panjang Kunci (bit)", [128, 192, 256], index=0)
    key_src = st.radio("Sumber Kunci", ["Generate acak", "Masukkan sendiri"], horizontal=True)
    out_encoding = st.selectbox("Tampilan output", ["base64", "hex"], index=0)
    advanced = st.checkbox("Tampilkan opsi lanjutan (IV/Nonce & AAD)")

    # Kunci
    if key_src == "Generate acak":
        key = random_key(key_bits)
        st.success("Kunci digenerate otomatis untuk sesi ini.")
    else:
        ktext = st.text_input("Kunci (hex/base64/teks) — panjang 16/24/32B", key="inp:key")
        key = to_bytes_from_hex_or_b64_or_utf8(ktext) if ktext else b""
        if key and (len(key) * 8) not in (128, 192, 256):
            st.error("Panjang kunci tidak sesuai (harus 16/24/32 byte).")

    # Opsi lanjutan
    if advanced:
        iv_text = st.text_input("IV/Nonce (hex/base64/teks) — opsional", key="inp:iv")
        aad_text = st.text_input("AAD untuk GCM (opsional, hex/base64/teks)", key="inp:aad")
    else:
        iv_text, aad_text = "", ""

tabs = st.tabs(["📝 Teks", "📄 File"])

# =========================
# Tab TEKS
# =========================
with tabs[0]:
    st.subheader("Enkripsi / Dekripsi Teks")
    action = st.radio("Aksi", ["Enkripsi", "Dekripsi"], horizontal=True, key="act:text")
    text = st.text_area(
        "Masukkan teks (plaintext untuk Enkripsi, atau ciphertext untuk Dekripsi)",
        height=140,
        key="inp:text",
    )

    if st.button("Proses (Teks)", key="btn:text"):
        if not key:
            st.error("Kunci kosong / tidak valid.")
        elif text is None or text == "":
            st.error("Masukkan teks terlebih dahulu.")
        else:
            try:
                aad = parse_aad(aad_text)
                iv_nonce = parse_iv_nonce(mode, iv_text)
                if iv_nonce is None:
                    st.stop()

                if action == "Enkripsi":
                    pt = text.encode("utf-8")
                    cipher = build_cipher(mode, key, iv_nonce, aad)

                    if mode == "CBC":
                        ct = cipher.encrypt(pkcs7_pad(pt))
                        show_bytes("Ciphertext", ct, out_encoding)
                        show_bytes("IV", iv_nonce, out_encoding)

                    elif mode == "CTR":
                        ct = cipher.encrypt(pt)
                        show_bytes("Ciphertext", ct, out_encoding)
                        show_bytes("Nonce", iv_nonce, out_encoding)

                    else:  # GCM
                        ct, tag = cipher.encrypt_and_digest(pt)
                        show_bytes("Ciphertext", ct, out_encoding)
                        show_bytes("Nonce", iv_nonce, out_encoding)
                        show_bytes("Tag", tag, out_encoding)

                    st.markdown("---")
                    st.caption("🔑 Parameter yang dipakai")
                    show_bytes("Key", key, out_encoding)
                    if mode == "CBC":
                        show_bytes("IV", iv_nonce, out_encoding)
                    elif mode == "CTR":
                        show_bytes("Nonce", iv_nonce, out_encoding)
                    else:
                        show_bytes("Nonce", iv_nonce, out_encoding)
                        if "tag" in locals():
                            show_bytes("Tag", tag, out_encoding)
                    if aad:
                        show_bytes("AAD", aad, out_encoding)

                else:  # Dekripsi
                    ct = to_bytes_from_hex_or_b64_or_utf8(text)

                    if mode == "CBC":
                        cipher = build_cipher(mode, key, iv_nonce, aad)
                        pt = pkcs7_unpad(cipher.decrypt(ct))
                        st.text_area("Plaintext", pt.decode("utf-8", errors="replace"), height=140, key="out:text:cbc")

                    elif mode == "CTR":
                        cipher = build_cipher(mode, key, iv_nonce, aad)
                        pt = cipher.decrypt(ct)
                        st.text_area("Plaintext", pt.decode("utf-8", errors="replace"), height=140, key="out:text:ctr")

                    else:  # GCM
                        tag_text = st.text_input("Masukkan Tag (hex/base64/teks) untuk GCM", key="inp:tag:gcm")
                        if not tag_text.strip():
                            st.error("Tag diperlukan untuk dekripsi GCM.")
                            st.stop()
                        tag = to_bytes_from_hex_or_b64_or_utf8(tag_text)
                        cipher = build_cipher(mode, key, iv_nonce, aad)
                        try:
                            pt = cipher.decrypt_and_verify(ct, tag)
                            st.text_area("Plaintext", pt.decode("utf-8", errors="replace"), height=140, key="out:text:gcm")
                        except Exception as e:
                            st.error(f"Verifikasi tag gagal: {e}")

                    st.markdown("---")
                    st.caption("🔑 Parameter yang dipakai")
                    show_bytes("Key", key, out_encoding)
                    if mode == "CBC":
                        show_bytes("IV", iv_nonce, out_encoding)
                    elif mode == "CTR":
                        show_bytes("Nonce", iv_nonce, out_encoding)
                    else:
                        show_bytes("Nonce", iv_nonce, out_encoding)

                    if aad:
                        show_bytes("AAD", aad, out_encoding)

            except Exception as e:
                st.error(f"Terjadi kesalahan: {e}")

# =========================
# Tab FILE
# =========================
with tabs[1]:
    st.subheader("Enkripsi / Dekripsi File")
    action_f = st.radio("Aksi (File)", ["Enkripsi", "Dekripsi"], horizontal=True, key="act:file")
    up = st.file_uploader("Pilih file (teks/biner apa pun)", type=None, key="upl:file")

    if st.button("Proses (File)", key="btn:file"):
        if not key:
            st.error("Kunci kosong / tidak valid.")
        elif not up:
            st.error("Pilih file terlebih dahulu.")
        else:
            try:
                aad = parse_aad(aad_text)
                iv_nonce = parse_iv_nonce(mode, iv_text)
                if iv_nonce is None:
                    st.stop()

                data = up.read()

                if action_f == "Enkripsi":
                    cipher = build_cipher(mode, key, iv_nonce, aad)
                    if mode == "CBC":
                        ct = cipher.encrypt(pkcs7_pad(data))
                        tag = b""
                    elif mode == "CTR":
                        ct = cipher.encrypt(data)
                        tag = b""
                    else:
                        ct, tag = cipher.encrypt_and_digest(data)

                    header = {
                        "mode": mode,
                        "key_bits": key_bits,
                        "iv_nonce": b64e(iv_nonce),
                        "tag": b64e(tag) if tag else "",
                        "aad": b64e(aad) if aad else "",
                    }
                    header_bytes = (str(header) + "\n---HEADER-END---\n").encode("utf-8")
                    payload = header_bytes + ct

                    st.download_button(
                        "⬇️ Unduh Hasil Enkripsi",
                        data=payload,
                        file_name=f"{up.name}.enc",
                        mime="application/octet-stream",
                        key="dl:enc",
                    )

                    st.markdown("---")
                    st.caption("🔑 Parameter yang dipakai")
                    show_bytes("Key", key, out_encoding)
                    if mode == "CBC":
                        show_bytes("IV", iv_nonce, out_encoding)
                    elif mode == "CTR":
                        show_bytes("Nonce", iv_nonce, out_encoding)
                    else:
                        show_bytes("Nonce", iv_nonce, out_encoding)
                        show_bytes("Tag", tag, out_encoding)
                    if aad:
                        show_bytes("AAD", aad, out_encoding)

                else:  # Dekripsi
                    sep = b"\n---HEADER-END---\n"
                    if sep not in data:
                        st.error("File tidak memiliki header metadata. Pastikan file berasal dari aplikasi ini.")
                        st.stop()
                    header_bytes, ct = data.split(sep, 1)
                    header = literal_eval(header_bytes.decode("utf-8"))

                    mode_h = header.get("mode", "")
                    if mode_h not in ("CBC", "CTR", "GCM"):
                        st.error("Mode pada header tidak dikenal.")
                        st.stop()
                    if mode_h != mode:
                        st.info(f"Mode pada header: {mode_h}. Menggunakan mode dari header.")

                    iv_nonce_h = b64d(header.get("iv_nonce", "")) if header.get("iv_nonce", "") else None
                    tag_h = b64d(header.get("tag", "")) if header.get("tag", "") else None
                    aad_h = b64d(header.get("aad", "")) if header.get("aad", "") else None

                    cipher = build_cipher(mode_h, key, iv_nonce_h, aad_h)
                    try:
                        if mode_h == "CBC":
                            pt = pkcs7_unpad(cipher.decrypt(ct))
                        elif mode_h == "CTR":
                            pt = cipher.decrypt(ct)
                        else:
                            if tag_h is None:
                                st.error("Tag GCM tidak tersedia dalam header.")
                                st.stop()
                            pt = cipher.decrypt_and_verify(ct, tag_h)

                        st.success("Dekripsi berhasil.")
                        st.download_button(
                            "⬇️ Unduh Hasil Dekripsi",
                            data=pt,
                            file_name=f"decrypted_{up.name.replace('.enc','')}",
                            mime="application/octet-stream",
                            key="dl:dec",
                        )
                    except Exception as e:
                        st.error(f"Dekripsi gagal: {e}")

            except Exception as e:
                st.error(f"Terjadi kesalahan: {e}")

# =========================
# Catatan keamanan
# =========================
st.markdown("---")
with st.expander("🛡️ Catatan Keamanan Penting"):
    st.markdown(
        """
- **GCM** direkomendasikan karena menyediakan *confidentiality* **dan** *integrity* (tag autentikasi).
- **JANGAN** menggunakan kembali IV/Nonce untuk kombinasi **(kunci, mode)** yang sama.
- Simpan kunci di secret manager (bukan hard-coded).
- Untuk produksi, gunakan format kemasan metadata yang tegas (mis. Protobuf/ASN.1) dan validasi input secara ketat.
"""
    )
