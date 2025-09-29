import base64
import io
import json
import re
from datetime import datetime

import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

# =============== Helpers ===============

def generate_rsa_keypair(bits: int = 2048) -> tuple[bytes, bytes]:
    key = RSA.generate(bits)
    private_pem = key.export_key(format="PEM")
    public_pem = key.publickey().export_key(format="PEM")
    return private_pem, public_pem

def _oaep_cipher_from_pub(pub_pem: bytes) -> PKCS1_OAEP.PKCS1OAEP_Cipher:
    pub_key = RSA.import_key(pub_pem)
    return PKCS1_OAEP.new(pub_key, hashAlgo=SHA256)

def _oaep_cipher_from_priv(priv_pem: bytes) -> PKCS1_OAEP.PKCS1OAEP_Cipher:
    priv_key = RSA.import_key(priv_pem)
    return PKCS1_OAEP.new(priv_key, hashAlgo=SHA256)

def rsa_oaep_chunk_size(pub_or_priv_pem: bytes) -> int:
    """Maximum plaintext bytes per RSA-OAEP block (SHA-256)."""
    key = RSA.import_key(pub_or_priv_pem)
    k = key.size_in_bytes()              # modulus length in bytes
    hlen = 32                            # SHA-256 digest size
    return k - 2 * hlen - 2              # RFC 8017

def rsa_encrypt_oaep_chunked(data: bytes, pub_pem: bytes) -> bytes:
    """
    Encrypt arbitrary length data with RSA-OAEP (SHA-256) using chunking.
    Output is concatenation of fixed-size RSA blocks (each exactly k bytes).
    """
    cipher = _oaep_cipher_from_pub(pub_pem)
    key = RSA.import_key(pub_pem)
    k = key.size_in_bytes()
    chunk_len = rsa_oaep_chunk_size(pub_pem)

    out = io.BytesIO()
    for i in range(0, len(data), chunk_len):
        block = data[i:i+chunk_len]
        ct = cipher.encrypt(block)       # length == k
        out.write(ct)
    return out.getvalue()

def rsa_decrypt_oaep_chunked(cipherblob: bytes, priv_pem: bytes) -> bytes:
    """
    Decrypt concatenated RSA-OAEP blocks. Splits by k (modulus bytes).
    """
    cipher = _oaep_cipher_from_priv(priv_pem)
    key = RSA.import_key(priv_pem)
    k = key.size_in_bytes()

    if len(cipherblob) % k != 0:
        raise ValueError("Ciphertext length is not a multiple of the RSA block size.")

    out = io.BytesIO()
    for i in range(0, len(cipherblob), k):
        block = cipher.decrypt(cipherblob[i:i+k])
        out.write(block)
    return out.getvalue()

def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")

def b64decode(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"), validate=True)

def valid_email(email: str) -> bool:
    # Simple RFC5322-ish email check
    return re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email) is not None

def download_bytes(filename: str, data: bytes, mime: str = "application/octet-stream"):
    st.download_button(
        label=f"⬇️ Download {filename}",
        data=data,
        file_name=filename,
        mime=mime,
        key=f"dl-{filename}"
    )

# =============== UI ===============

st.set_page_config(page_title="RSA Form Encryptor", page_icon="🔐", layout="centered")
st.title("🔐 RSA Form Encryptor (Streamlit)")

st.write(
    "Aplikasi demo **RSA-OAEP (SHA-256)** untuk mengenkripsi data form "
    "(**nama**, **email**, **pesan**). Mendukung *chunking* sehingga pesan panjang tetap bisa terenkripsi."
)

with st.sidebar:
    st.header("🔑 Manajemen Kunci")
    key_bits = st.selectbox("Panjang kunci (bits)", [2048, 3072, 4096], index=0, key="bits")

    colg1, colg2 = st.columns(2)
    with colg1:
        if st.button("🔧 Generate Keypair", key="gen"):
            priv, pub = generate_rsa_keypair(key_bits)
            st.session_state["private_pem"] = priv
            st.session_state["public_pem"] = pub
            st.success(f"Keypair {key_bits}-bit berhasil dibuat.")

    with colg2:
        st.write("")

    st.subheader("Unggah Kunci (Opsional)")
    up_pub = st.file_uploader("Public Key (.pem)", type=["pem"], key="up_pub")
    up_priv = st.file_uploader("Private Key (.pem)", type=["pem"], key="up_priv")

    if up_pub is not None:
        try:
            _ = RSA.import_key(up_pub.read())
            st.session_state["public_pem"] = _ .export_key()
            st.success("Public key dimuat.")
        except Exception as e:
            st.error(f"Gagal memuat public key: {e}")

    if up_priv is not None:
        try:
            up_priv.seek(0)
            priv_pem = up_priv.read()
            _ = RSA.import_key(priv_pem)
            st.session_state["private_pem"] = priv_pem
            st.success("Private key dimuat.")
        except Exception as e:
            st.error(f"Gagal memuat private key: {e}")

    st.divider()
    if "public_pem" in st.session_state:
        download_bytes("public.pem", st.session_state["public_pem"], "application/x-pem-file")
    if "private_pem" in st.session_state:
        download_bytes("private.pem", st.session_state["private_pem"], "application/x-pem-file")

# =============== Encryption Form ===============

st.subheader("✉️ Enkripsi Data Form")

with st.form("encrypt_form", clear_on_submit=False):
    name = st.text_input("Nama", max_chars=120, key="name")
    email = st.text_input("Email", max_chars=120, key="email")
    message = st.text_area("Pesan", height=160, key="message")
    use_timestamp = st.checkbox("Sertakan timestamp", value=True, key="ts")
    submitted = st.form_submit_button("🔒 Enkripsi dengan RSA-OAEP")

if submitted:
    if not name.strip():
        st.error("Nama tidak boleh kosong.")
    elif not email.strip() or not valid_email(email.strip()):
        st.error("Email tidak valid.")
    elif not message.strip():
        st.error("Pesan tidak boleh kosong.")
    elif "public_pem" not in st.session_state:
        st.error("Public key belum tersedia. Generate atau unggah public key terlebih dahulu.")
    else:
        payload = {
            "nama": name.strip(),
            "email": email.strip(),
            "pesan": message,
        }
        if use_timestamp:
            payload["timestamp"] = datetime.utcnow().isoformat() + "Z"

        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        try:
            pub = st.session_state["public_pem"]
            # Info chunking
            chunk_len = rsa_oaep_chunk_size(pub)
            key_size_bytes = RSA.import_key(pub).size_in_bytes()
            st.info(
                f"Panjang plaintext: **{len(raw)}** byte • "
                f"Chunk RSA-OAEP: **{chunk_len}** byte • "
                f"Ukuran blok ciphertext RSA: **{key_size_bytes}** byte."
            )

            cipherblob = rsa_encrypt_oaep_chunked(raw, pub)
            b64 = b64encode(cipherblob)

            st.success("Enkripsi berhasil ✅")
            st.code(b64, language="text")

            st.download_button(
                label="⬇️ Download ciphertext (base64).txt",
                data=b64,
                file_name="ciphertext_base64.txt",
                mime="text/plain",
                key="dl-ct-b64",
            )

            st.download_button(
                label="⬇️ Download ciphertext.bin",
                data=cipherblob,
                file_name="ciphertext.bin",
                mime="application/octet-stream",
                key="dl-ct-bin",
            )

        except Exception as e:
            st.error(f"Gagal mengenkripsi: {e}")

# =============== Decryption ===============

st.subheader("🔓 Dekripsi")

col1, col2 = st.columns(2)

with col1:
    b64_input = st.text_area(
        "Tempel ciphertext (base64)",
        placeholder="Tempel ciphertext base64 di sini...",
        height=160,
        key="b64area"
    )

with col2:
    ct_file = st.file_uploader("Atau unggah ciphertext.bin", type=["bin"], key="ctbin")

if st.button("Dekripsi Sekarang", key="decbtn"):
    if "private_pem" not in st.session_state:
        st.error("Private key belum tersedia. Unggah atau generate private key terlebih dahulu.")
    else:
        try:
            if ct_file is not None:
                cipherblob = ct_file.read()
            elif b64_input.strip():
                cipherblob = b64decode(b64_input.strip())
            else:
                st.error("Masukkan ciphertext base64 ATAU unggah ciphertext.bin terlebih dahulu.")
                cipherblob = None

            if cipherblob:
                plain = rsa_decrypt_oaep_chunked(cipherblob, st.session_state["private_pem"])
                # Tampilkan JSON jika valid, jika tidak tampilkan raw text.
                try:
                    obj = json.loads(plain.decode("utf-8"))
                    st.success("Dekripsi berhasil ✅ (JSON)")
                    st.json(obj, expanded=True)
                except Exception:
                    st.success("Dekripsi berhasil ✅ (Teks)")
                    st.code(plain.decode("utf-8", errors="replace"))
        except Exception as e:
            st.error(f"Gagal mendekripsi: {e}")
