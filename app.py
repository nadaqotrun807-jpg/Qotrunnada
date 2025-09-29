import os
import uuid
import json
import base64
import sqlite3
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage

import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ===================== Konstanta & Util =====================
DB_DIR = "vault"
DB_PATH = os.path.join(DB_DIR, "submissions.db")

def ensure_db():
    os.makedirs(DB_DIR, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""
        CREATE TABLE IF NOT EXISTS submissions (
            id TEXT PRIMARY KEY,
            ts TEXT NOT NULL,
            sender TEXT,
            package_b64 TEXT NOT NULL,
            nonce_b64 TEXT NOT NULL,
            tag_b64 TEXT NOT NULL,
            ciphertext_b64 TEXT NOT NULL
        )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_ts ON submissions(ts)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_sender ON submissions(sender)")
        conn.commit()

def db_insert(record: dict):
    with sqlite3.connect(DB_PATH) as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO submissions (id, ts, sender, package_b64, nonce_b64, tag_b64, ciphertext_b64)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (record["id"], record["ts"], record["sender"], record["package_b64"],
              record["nonce_b64"], record["tag_b64"], record["ciphertext_b64"]))
        conn.commit()

def db_list(search: str | None = None) -> list[dict]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        if search:
            q = f"%{search.lower()}%"
            c.execute("""
                SELECT * FROM submissions
                WHERE lower(id) LIKE ? OR lower(sender) LIKE ?
                ORDER BY ts DESC
            """, (q, q))
        else:
            c.execute("SELECT * FROM submissions ORDER BY ts DESC")
        rows = c.fetchall()
        return [dict(r) for r in rows]

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))

def load_secrets():
    admin_pw = st.secrets.get("ADMIN_PASSWORD")
    key_hex  = st.secrets.get("AES128_KEY_HEX")
    smtp = {
        "host": st.secrets.get("SMTP_HOST"),
        "port": st.secrets.get("SMTP_PORT"),
        "user": st.secrets.get("SMTP_USER"),
        "pass": st.secrets.get("SMTP_PASS"),
        "from_email": st.secrets.get("FROM_EMAIL"),
        "admin_email": st.secrets.get("ADMIN_EMAIL"),
    }

    if not admin_pw or not key_hex:
        st.warning("⚠️ ADMIN_PASSWORD atau AES128_KEY_HEX belum diset di secrets.")

    key_bytes = None
    if key_hex:
        hx = key_hex.strip().lower().replace("0x", "")
        if len(hx) != 32:
            st.error("AES128_KEY_HEX harus 32 digit hex (128-bit).")
        else:
            try:
                key_bytes = bytes.fromhex(hx)
            except Exception as e:
                st.error(f"Kunci hex tidak valid: {e}")

    return admin_pw, key_bytes, smtp

# ===================== Kripto =====================
def aes_gcm_encrypt(plaintext: str, key: bytes) -> dict:
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

# ===================== Email =====================
def smtp_config_ok(smtp: dict) -> bool:
    keys = ["host", "port", "user", "pass", "from_email", "admin_email"]
    return all(smtp.get(k) for k in keys)

def send_admin_notification(record: dict, smtp: dict) -> tuple[bool, str]:
    if not smtp_config_ok(smtp):
        return False, "Konfigurasi SMTP tidak lengkap."

    msg = EmailMessage()
    msg["Subject"] = f"[AES-128 GCM] Pesan Baru • {record.get('id')}"
    msg["From"] = smtp["from_email"]
    msg["To"] = smtp["admin_email"]

    preview = record.get("ciphertext_b64", "")[:64] + "..." if record.get("ciphertext_b64") else "(kosong)"
    body = (
        f"Hai Admin,\n\n"
        f"Ada pengiriman pesan baru yang berhasil DIENKRIPSI.\n\n"
        f"ID: {record.get('id')}\n"
        f"Waktu (UTC): {record.get('ts')}\n"
        f"Pengirim: {record.get('sender')}\n"
        f"Cipher (preview, base64): {preview}\n\n"
        f"Gunakan panel admin untuk mendekripsi.\n"
    )
    msg.set_content(body)

    html = f"""
    <html><body>
      <p>Hai Admin,</p>
      <p>Ada pengiriman pesan baru yang berhasil <b>DIENKRIPSI</b>.</p>
      <ul>
        <li><b>ID:</b> {record.get('id')}</li>
        <li><b>Waktu (UTC):</b> {record.get('ts')}</li>
        <li><b>Pengirim:</b> {record.get('sender')}</li>
        <li><b>Cipher (preview, base64):</b> <code>{preview}</code></li>
      </ul>
      <p>Gunakan panel admin untuk mendekripsi.</p>
    </body></html>
    """
    msg.add_alternative(html, subtype="html")

    try:
        with smtplib.SMTP(smtp["host"], int(smtp["port"])) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp["user"], smtp["pass"])
            server.send_message(msg)
        return True, "Notifikasi email terkirim."
    except Exception as e:
        return False, f"Gagal kirim email: {e}"

# ===================== UI =====================
st.set_page_config(page_title="AES-128 GCM • Publik & Admin (SQLite)", page_icon="🔐", layout="centered")
st.title("🔐 AES-128 (GCM) — Form Publik & Panel Admin (SQLite)")

st.caption(
    "Publik mengirim pesan → server <b>mengenkripsi</b> dan menyimpan ke <code>vault/submissions.db</code>. "
    "Admin login untuk <b>lihat & dekripsi</b>. Email notifikasi opsional.",
    unsafe_allow_html=True,
)

ensure_db()
admin_pw_secret, aes_key, smtp = load_secrets()
mode = st.radio("Pilih Mode", ["📝 Kirim Pesan (Publik)", "🛡️ Panel Admin"], horizontal=True)

# ---------- Mode Publik ----------
if mode == "📝 Kirim Pesan (Publik)":
    st.subheader("Form Pengiriman Pesan")
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
                rec = {
                    "id": str(uuid.uuid4()),
                    "ts": now_iso(),
                    "sender": sender.strip() or "Anonim",
                    "package_b64": enc["package_b64"],
                    "nonce_b64": enc["nonce_b64"],
                    "tag_b64": enc["tag_b64"],
                    "ciphertext_b64": enc["ciphertext_b64"],
                }
                db_insert(rec)

                ok, info = send_admin_notification(rec, smtp)
                if ok:
                    st.success("Pesan terenkripsi & tersimpan (SQLite). Notifikasi email terkirim. ✅")
                else:
                    st.success("Pesan terenkripsi & tersimpan (SQLite).")
                    st.warning(info)

                st.info(f"Kode Referensi: **{rec['id']}** — simpan jika perlu verifikasi ke admin.")
            except Exception as e:
                st.error(f"Gagal memproses: {e}")

# ---------- Mode Admin ----------
else:
    st.subheader("Login Admin")
    admin_pw_input = st.text_input("Password Admin", type="password")

    if st.button("Masuk") or st.session_state.get("admin_ok"):
        if not admin_pw_secret:
            st.error("ADMIN_PASSWORD belum diset.")
        elif admin_pw_input == admin_pw_secret or st.session_state.get("admin_ok"):
            st.session_state["admin_ok"] = True
            if aes_key is None:
                st.error("AES128_KEY_HEX belum diset atau tidak valid.")
            else:
                st.success("Login admin berhasil.")

                st.write("### Daftar Pesan Terenkripsi (SQLite)")
                q = st.text_input("Cari (ID / Nama pengirim)", placeholder="Ketik ID atau nama…")
                items = db_list(q.strip() or None)

                if not items:
                    st.info("Belum ada entri.")
                else:
                    options = [f"{it['ts']} • {it['sender']} • {it['id']}" for it in items]
                    pick = st.selectbox("Pilih entri untuk didekripsi", options)
                    chosen = items[options.index(pick)]

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

                    # Ekspor seluruh entri (opsional)
                    if st.download_button(
                        "⬇️ Ekspor Semua Entri (JSON)",
                        data=json.dumps(items, ensure_ascii=False, indent=2),
                        file_name="submissions_export.json",
                        mime="application/json",
                    ):
                        pass
        else:
            st.error("Password admin salah.")
