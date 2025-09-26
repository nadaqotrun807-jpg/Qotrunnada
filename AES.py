import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding
import base64
import io

# ---------- Util umum ----------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode('utf-8')

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode('utf-8'))

def to_bytes_from_hex_or_b64_or_utf8(s: str) -> bytes:
    """Coba parse sebagai hex -> base64 -> utf-8 (fallback)."""
    s = s.strip()
    # Hex?
    try:
        return bytes.fromhex(s)
    except Exception:
        pass
    # Base64?
    try:
        return b64d(s)
    except Exception:
        pass
    # UTF-8 (langsung)
    return s.encode('utf-8')

def random_key(bits: int) -> bytes:
    assert bits in (128, 192, 256)
    return get_random_bytes(bits // 8)

def generate_iv(mode: str) -> bytes:
    # CBC: 16 bytes IV; CTR: 16 bytes nonce (PyCryptodome sebut nonce, aman 8-16)
    # GCM: 12 bytes nonce direkomendasikan
    if mode == "CBC":
        return get_random_bytes(16)
    elif mode == "CTR":
        return get_random_bytes(16)
    elif mode == "GCM":
        return get_random_bytes(12)
    else:
        raise ValueError("Mode tidak dikenal")

def build_cipher(mode: str, key: bytes, iv_or_nonce: bytes, aad: bytes | None = None, for_encrypt=True):
    if mode == "CBC":
        cipher = AES.new(key, AES.MODE_CBC, iv=iv_or_nonce)
        return cipher
    elif mode == "CTR":
        cipher = AES.new(key, AES.MODE_CTR, nonce=iv_or_nonce)
        return cipher
    elif mode == "GCM":
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv_or_nonce)
        if aad:
            cipher.update(aad)
        return cipher
    else:
        raise ValueError("Mode tidak dikenal")

def pkcs7_pad(data: bytes) -> bytes:
    return Padding.pad(data, 16, style='pkcs7')

def pkcs7_unpad(data: bytes) -> bytes:
    return Padding.unpad(data, 16, style='pkcs7')

# ---------- UI ----------
st.set_page_config(page_title="AES Streamlit", page_icon="🔐", layout="centered")
st.title("🔐 AES Encrypt/Decrypt (CBC / CTR / GCM)")

with st.sidebar:
    st.header("⚙️ Pengaturan")
    mode = st.selectbox("Mode AES", ["GCM", "CBC", "CTR"], help="GCM (disarankan, dengan autentikasi), CBC (butuh padding), CTR (stream-like)")
    key_bits = st.selectbox("Panjang Kunci (bit)", [128, 192, 256])
    key_input_mode = st.radio("Sumber Kunci", ["Generate acak", "Masukkan sendiri"], horizontal=True)
    show_advanced = st.checkbox("Tampilkan opsi lanjutan (IV/Nonce, AAD, encoding tampilan)")

    if key_input_mode == "Generate acak":
        key = random_key(key_bits)
        st.success("Kunci digenerate otomatis.")
    else:
        k = st.text_input("Kunci (hex / base64 / teks)", value="")
        if k:
            key = to_bytes_from_hex_or_b64_or_utf8(k)
            if len(key) * 8 not in (128, 192, 256):
                st.error("Panjang kunci tidak sesuai (harus 16/24/32 byte).")
        else:
            key = b""

    out_encoding = st.selectbox("Tampilan output", ["base64", "hex"], index=0)

    if show_advanced:
        iv_user = st.text_input(
            ("IV (CBC/CTR 16B) / Nonce (GCM 12B) — opsional; "
             "jika kosong akan digenerate acak. (hex/base64/teks)")
        )
        aad_text = st.text_input("AAD untuk GCM (opsional, hex/base64/teks)", value="")
    else:
        iv_user, aad_text = "", ""

tabs = st.tabs(["📝 Teks", "📄 File"])

# ---------- Helper tampilan ----------
def display_bytes(label, b: bytes):
    if out_encoding == "base64":
        st.text_input(label, b64e(b), key=f"{label}-{hash(b)}")
    else:
        st.text_input(label, b.hex(), key=f"{label}-{hash(b)}")

def parse_iv_nonce(mode: str, iv_user: str | None):
    if iv_user and iv_user.strip():
        raw = to_bytes_from_hex_or_b64_or_utf8(iv_user)
        # Validasi panjang
        if mode == "CBC" and len(raw) != 16:
            st.error("IV CBC harus 16 byte.")
            return None
        if mode == "CTR" and not (8 <= len(raw) <= 16):
            st.error("Nonce CTR disarankan 8-16 byte.")
            return None
        if mode == "GCM" and len(raw) != 12:
            st.error("Nonce GCM direkomendasikan 12 byte.")
            return None
        return raw
    else:
        return generate_iv(mode)

def parse_aad(aad_text: str) -> bytes | None:
    if not aad_text.strip():
        return None
    return to_bytes_from_hex_or_b64_or_utf8(aad_text)

# ---------- Teks Tab ----------
with tabs[0]:
    st.subheader("Enkripsi / Dekripsi Teks")
    choice = st.radio("Aksi", ["Enkripsi", "Dekripsi"], horizontal=True)
    text = st.text_area("Masukkan teks (plaintext saat enkripsi, ciphertext saat dekripsi)", height=150)

    if st.button("Proses (Teks)"):
        if not key:
            st.error("Kunci tidak valid / kosong.")
        elif not text:
            st.error("Masukkan teks terlebih dahulu.")
        else:
            try:
                aad = parse_aad(aad_text)
                iv_nonce = parse_iv_nonce(mode, iv_user)
                if iv_nonce is None:
                    st.stop()

                if choice == "Enkripsi":
                    plain_bytes = text.encode('utf-8')
                    cipher = build_cipher(mode, key, iv_nonce, aad, for_encrypt=True)

                    if mode == "CBC":
                        ct = cipher.encrypt(pkcs7_pad(plain_bytes))
                        display_bytes("Ciphertext", ct)
                        display_bytes("IV", iv_nonce)

                    elif mode == "CTR":
                        ct = cipher.encrypt(plain_bytes)
                        display_bytes("Ciphertext", ct)
                        display_bytes("Nonce", iv_nonce)

                    elif mode == "GCM":
                        ct, tag = cipher.encrypt_and_digest(plain_bytes)
                        display_bytes("Ciphertext", ct)
                        display_bytes("Nonce", iv_nonce)
                        display_bytes("Tag", tag)

                else:  # Dekripsi
                    # Untuk input ciphertext, kita coba auto-deteksi base64/hex/teks mentah
                    ct = to_bytes_from_hex_or_b64_or_utf8(text)
                    if mode == "CBC":
                        cipher = build_cipher(mode, key, iv_nonce, aad, for_encrypt=False)
                        pt = pkcs7_unpad(cipher.decrypt(ct))
                        st.text_area("Plaintext", pt.decode('utf-8', errors='replace'), height=150)

                    elif mode == "CTR":
                        cipher = build_cipher(mode, key, iv_nonce, aad, for_encrypt=False)
                        pt = cipher.decrypt(ct)
                        st.text_area("Plaintext", pt.decode('utf-8', errors='replace'), height=150)

                    elif mode == "GCM":
                        tag_in = st.text_input("Masukkan Tag (hex/base64/teks) untuk GCM", value="", key="tag-text")
                        if not tag_in.strip():
                            st.error("Tag diperlukan untuk dekripsi GCM.")
                            st.stop()
                        tag = to_bytes_from_hex_or_b64_or_utf8(tag_in)
                        cipher = build_cipher(mode, key, iv_nonce, aad, for_encrypt=False)
                        try:
                            pt = cipher.decrypt_and_verify(ct, tag)
                            st.text_area("Plaintext", pt.decode('utf-8', errors='replace'), height=150)
                        except Exception as e:
                            st.error(f"Verifikasi tag gagal: {e}")

                # Tampilkan kembali kunci & parameter
                st.markdown("---")
                st.caption("🔑 Parameter yang dipakai")
                display_bytes("Key", key)
                if mode == "CBC":
                    display_bytes("IV", iv_nonce)
                elif mode == "CTR":
                    display_bytes("Nonce", iv_nonce)
                elif mode == "GCM":
                    display_bytes("Nonce", iv_nonce)
                    if choice == "Enkripsi" and 'tag' in locals():
                        display_bytes("Tag", tag)

                if aad:
                    display_bytes("AAD", aad)

            except Exception as e:
                st.error(f"Terjadi kesalahan: {e}")

# ---------- File Tab ----------
with tabs[1]:
    st.subheader("Enkripsi / Dekripsi File")
    choice_f = st.radio("Aksi (File)", ["Enkripsi", "Dekripsi"], horizontal=True, key="file-action")
    file = st.file_uploader("Pilih file (teks atau biner apa pun)", type=None)

    if st.button("Proses (File)"):
        if not key:
            st.error("Kunci tidak valid / kosong.")
        elif not file:
            st.error("Pilih file terlebih dahulu.")
        else:
            try:
                aad = parse_aad(aad_text)
                iv_nonce = parse_iv_nonce(mode, iv_user)
                if iv_nonce is None:
                    st.stop()

                data = file.read()
                cipher = build_cipher(mode, key, iv_nonce, aad, for_encrypt=(choice_f=="Enkripsi"))
                out = b""

                if choice_f == "Enkripsi":
                    if mode == "CBC":
                        out = cipher.encrypt(pkcs7_pad(data))
                    elif mode == "CTR":
                        out = cipher.encrypt(data)
                    elif mode == "GCM":
                        out, tag = cipher.encrypt_and_digest(data)

                    # Kemasi metadata sederhana (nonce/iv dan tag untuk GCM) di header b64
                    header = {
                        "mode": mode,
                        "key_bits": key_bits,
                        "iv_nonce": b64e(iv_nonce),
                        "tag": b64e(tag) if mode == "GCM" else "",
                        "aad": b64e(aad) if aad else "",
                    }
                    header_bytes = (str(header) + "\n---HEADER-END---\n").encode('utf-8')
                    payload = header_bytes + out

                    st.download_button(
                        "⬇️ Unduh Hasil Enkripsi",
                        data=payload,
                        file_name=f"{file.name}.enc",
                        mime="application/octet-stream",
                    )

                    st.markdown("---")
                    st.caption("🔑 Parameter yang dipakai")
                    display_bytes("Key", key)
                    if mode == "CBC":
                        display_bytes("IV", iv_nonce)
                    elif mode == "CTR":
                        display_bytes("Nonce", iv_nonce)
                    elif mode == "GCM":
                        display_bytes("Nonce", iv_nonce)
                        display_bytes("Tag", tag)
                    if aad:
                        display_bytes("AAD", aad)

                else:
                    # Dekripsi: baca header
                    content = data
                    sep = b"\n---HEADER-END---\n"
                    if sep not in content:
                        st.error("File tidak memiliki header metadata (mode/IV/tag). Pastikan file berasal dari aplikasi ini.")
                        st.stop()
                    header_bytes, ct = content.split(sep, 1)
                    header_str = header_bytes.decode('utf-8')
                    # Evaluasi aman: parse dict via literal_eval
                    from ast import literal_eval
                    header = literal_eval(header_str)

                    mode_h = header.get("mode", "")
                    if mode_h != mode:
                        st.warning(f"Mode pada header adalah {mode_h}. Anda memilih {mode}. Mengikuti header: {mode_h}.")
                        mode_h = mode_h  # gunakan yang dari header
                    iv_nonce_h = b64d(header.get("iv_nonce", "")) if header.get("iv_nonce", "") else None
                    tag_h = b64d(header.get("tag", "")) if header.get("tag", "") else None
                    aad_h = b64d(header.get("aad", "")) if header.get("aad", "") else None

                    cipher = build_cipher(mode_h, key, iv_nonce_h, aad_h, for_encrypt=False)

                    try:
                        if mode_h == "CBC":
                            pt = pkcs7_unpad(cipher.decrypt(ct))
                        elif mode_h == "CTR":
                            pt = cipher.decrypt(ct)
                        elif mode_h == "GCM":
                            if tag_h is None:
                                st.error("Tag GCM tidak tersedia dalam header.")
                                st.stop()
                            pt = cipher.decrypt_and_verify(ct, tag_h)
                        else:
                            st.error("Mode pada header tidak dikenal.")
                            st.stop()

                        st.success("Dekripsi berhasil.")
                        # Tombol unduh hasil
                        st.download_button(
                            "⬇️ Unduh Hasil Dekripsi",
                            data=pt,
                            file_name=f"decrypted_{file.name.replace('.enc','')}",
                            mime="application/octet-stream",
                        )
                    except Exception as e:
                        st.error(f"Dekripsi gagal: {e}")

            except Exception as e:
                st.error(f"Terjadi kesalahan: {e}")

# ---------- Catatan Keamanan ----------
st.markdown("---")
with st.expander("🛡️ Catatan Keamanan Penting"):
    st.markdown(
        """
- **GCM** direkomendasikan karena menyediakan *confidentiality* dan *integrity* (dengan Tag autentikasi).
- **Jangan pernah menggunakan kembali Nonce/IV** untuk kombinasi **(kunci, mode)** yang sama—gunakan yang acak setiap enkripsi.
- Simpan **kunci** secara aman (contoh: KMS/secret manager), bukan hard-coded.
- Untuk produksi, gunakan skema kemasan yang tegas (mis. format header biner atau ASN.1/Protobuf) serta validasi input ketat.
"""
    )
