import base64
import json
import os
import uuid
from datetime import datetime, timezone
import streamlit as st
from Crypto.Cipher import AES

# ===================== Konfigurasi & Utilitas =====================

# Lokasi penyimpanan server-side untuk ciphertext
VAULT_DIR = "vault"
VAULT_FILE = os.path.join(VAULT_DIR, "submissions.jsonl")

def ensure_vault():
    os.makedirs(VAULT_DIR, exist_ok=True)
    if not os.path.exists(VAULT_FILE):
        with open(VAULT_FILE, "w", encoding="utf-8"):
            pass

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def load_secrets():
    # Ambil kunci & password admin dari secrets
    admin_pw = st.secrets.get("ADMIN_PASSWORD", None)
    key_hex = st.secrets.get("AES128_KEY_HEX", None)
    if not admin_pw or not key_hex:
        st.warning(
            "⚠️ ADMIN_PASSWORD atau AES128_KEY_HEX belum diset di secrets. "
            "Gunakan `.streamlit/secrets.toml` saat lokal, atau App Secrets jika di Streamlit Cloud."
        )
    key_bytes = None
    if key_hex:
        key_hex = key_hex.strip().lower().replace("0x", "")
        if len(key_hex) != 32:
            st.error("AES128_KEY_HEX harus 32 digit hex (128-bit).")
        else:
            try:
                key_bytes = bytes.fromhex(key_hex)
            except Exception as e:
                st.error(f"Kunci hex tidak valid: {e}")
    return admin_pw, key_bytes

def aes_gcm_encrypt(plaintext: str, key: bytes) -> dict:
    """
    Enkripsi dengan AES-128 GCM.
    Paket = base64(nonce || tag || ciphertext)
    """
    from Crypto.Random import get_random_bytes
    nonce = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode("utf-8"))
    packed = nonce + tag + ciphertext
    return {
        "nonce_b64": b64e(nonce),
        "tag_b64": b64e(tag),
        "ciphertext_b64": b64e(ciphertext),
        "package_b64": b64e(packed),
    }

def aes_gcm_decrypt(package_b64: str, key: bytes) -> str:
    packed = b64d(package_b64)
    if len(packed) < 12 + 16 + 1:
        raise ValueError("Paket tidak valid atau terlalu pendek.")
    nonce = packed[:12]
    tag = packed[12:28]
    ciphertext = packed[28:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    pt = cipher.decrypt_and_verify(ciphertext, tag)
    return pt.decode("utf-8")

def vault_append(record: dict) -> None:
    ensure_vault()
    with open(VAULT_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

def vault_read_all() -> list:
    ensure_vault()
    items = []
    with open(VAULT_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return items

# ===================== UI =====================

st.set_page_config(page_title="AES-128 GCM • Publik & Admin", page_icon="🔐", layout="centered")
st.title("🔐 AES-128 (GCM) — Form Publik & Panel Admin")

st.caption(
    "Publik dapat **mengirim pesan**. Ciphertext **tidak ditampilkan** ke publik dan hanya **disimpan di server**. "
    "Admin dapat **melihat & mendekripsi** setelah login."
)

admin_pw_secret, aes_key = load_secrets()

mode = st.radio("Pilih Mode", ["📝 Kirim Pesan (Publik)", "🛡️ Panel Admin"], horizontal=True)

# ===================== Mode Publik =====================
if mode == "📝 Kirim Pesan (Publik)":
    st.subheader("Form Pengiriman Pesan")
    st.write("Isi pesan di bawah ini. Pesan akan **dienkripsi** dan **disimpan aman**. "
             "Kamu akan mendapat **kode referensi** — simpan jika perlu.")

    with st.form("public_form", clear_on_submit=True):
        sender = st.text_input("Nama / Identitas pengirim (opsional)", placeholder="Anonim")
        message = st.text_area("Pesan (plaintext)", height=160, placeholder="Tulis pesan kamu di sini...")
        submitted = st.form_submit_button("Kirim & Enkripsi")

    if submitted:
        if aes_key is None:
            st.error("Kunci AES belum siap. Hubungi admin.")
        elif not message.strip():
            st.warning("Pesan tidak boleh kosong.")
        else:
            try:
                enc = aes_gcm_encrypt(message.strip(), aes_key)
                ref_id = str(uuid.uuid4())
                record = {
                    "id": ref_id,
                    "ts": now_iso(),
                    "sender": sender.strip() or "Anonim",
                    "package_b64": enc["package_b64"],
                    # simpan juga komponen jika diperlukan audit
                    "nonce_b64": enc["nonce_b64"],
                    "tag_b64": enc["tag_b64"],
                    "ciphertext_b64": enc["ciphertext_b64"],
                }
                vault_append(record)

                # ❗ Tidak menampilkan ciphertext ke publik
                st.success("Pesan berhasil dienkripsi & disimpan aman. Terima kasih! 🙌")
                st.info(f"Kode Referensi: **{ref_id}**\n\n"
                        "Simpan kode ini jika suatu saat perlu konfirmasi ke admin.")
            except Exception as e:
                st.error(f"Gagal memproses: {e}")

# ===================== Mode Admin =====================
else:
    st.subheader("Login Admin")
    admin_pw_input = st.text_input("Password Admin", type="password")

    if st.button("Masuk") or st.session_state.get("admin_ok"):
        if not admin_pw_secret:
            st.error("ADMIN_PASSWORD belum diset di secrets.")
        elif admin_pw_input == admin_pw_secret or st.session_state.get("admin_ok"):
            st.session_state["admin_ok"] = True
            if aes_key is None:
                st.error("AES128_KEY_HEX belum diset atau tidak valid.")
            else:
                st.success("Login admin berhasil.")

                # Tabel ringkas submissions
                items = vault_read_all()
                if not items:
                    st.info("Belum ada submission.")
                else:
                    # Urutkan terbaru dulu
                    items = sorted(items, key=lambda x: x.get("ts", ""), reverse=True)

                    # Filter pencarian sederhana
                    st.write("### Daftar Pesan Terenkripsi")
                    q = st.text_input("Cari (ID / Nama pengirim)", placeholder="Ketik ID atau nama...")
                    if q:
                        qlow = q.lower()
                        items_filtered = [
                            it for it in items
                            if qlow in it.get("id", "").lower() or qlow in it.get("sender", "").lower()
                        ]
                    else:
                        items_filtered = items

                    # Pilih salah satu untuk dibuka
                    options = [f"{it['ts']} • {it['sender']} • {it['id']}" for it in items_filtered]
                    if options:
                        pick = st.selectbox("Pilih entri untuk didekripsi", options)
                        idx = options.index(pick)
                        chosen = items_filtered[idx]

                        st.write("**Rincian Entri**")
                        st.json({
                            "id": chosen["id"],
                            "timestamp_utc": chosen["ts"],
                            "sender": chosen["sender"],
                        })

                        if st.button("🔓 Dekripsi Pesan Ini"):
                            try:
                                plaintext = aes_gcm_decrypt(chosen["package_b64"], aes_key)
                                st.success("Dekripsi sukses.")
                                st.text_area("Plaintext", value=plaintext, height=160)
                                st.code(chosen["package_b64"], language="text")
                            except Exception as e:
                                st.error(f"Gagal dekripsi: {e}")

                        # Ekspor utilitas
                        st.download_button(
                            "⬇️ Unduh Semua Entri (JSONL)",
                            data="\n".join(json.dumps(it, ensure_ascii=False) for it in items),
                            file_name="submissions.jsonl",
                            mime="text/plain",
                        )
                    else:
                        st.info("Tidak ada entri yang cocok dengan pencarian.")
        else:
            st.error("Password admin salah.")
