# hybrid_rsa_aes.py
# ==========================================================
# HYBRID CRYPTOGRAPHY (RSA-OAEP + AES-GCM) + TIMING
# - AES-GCM mengenkripsi plaintext -> ciphertext + nonce + tag
# - RSA-OAEP mengenkripsi kunci AES (key wrapping)
# - Waktu diukur dengan time.perf_counter() untuk analisis empiris
# ==========================================================

import json, base64
from time import perf_counter
from dataclasses import dataclass

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# ---------- Helper encoding ----------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode('ascii'))

# ---------- Data classes for clarity ----------
@dataclass
class EncTiming:
    t_aes_enc: float
    t_rsa_enc: float
    t_total_enc: float

@dataclass
class DecTiming:
    t_rsa_dec: float
    t_aes_dec: float
    t_total_dec: float

# ---------- RSA key utilities ----------
def generate_rsa_keys(bits: int = 3072) -> tuple[bytes, bytes]:
    """
    Return: (public_key_pem, private_key_pem)
    """
    key = RSA.generate(bits)
    return key.public_key().export_key(), key.export_key()

def load_public_key(pem: bytes):
    return RSA.import_key(pem)

def load_private_key(pem: bytes):
    return RSA.import_key(pem)

# ---------- Hybrid Encrypt ----------
def hybrid_encrypt(plaintext: bytes, public_key_pem: bytes, aes_bits: int = 128) -> tuple[dict, EncTiming]:
    """
    Encrypt plaintext with AES-GCM; wrap AES key with RSA-OAEP.
    Returns:
      payload (dict, b64 fields) and EncTiming
    """
    if aes_bits not in (128, 192, 256):
        raise ValueError("aes_bits must be one of {128, 192, 256}")
    aes_len = aes_bits // 8

    # AES-GCM
    t0 = perf_counter()
    aes_key = get_random_bytes(aes_len)
    cipher = AES.new(aes_key, AES.MODE_GCM)     # nonce generated automatically (12–16 bytes)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    nonce = cipher.nonce
    t1 = perf_counter()
    t_aes_enc = t1 - t0

    # RSA-OAEP (wrap AES key)
    t2 = perf_counter()
    pub = load_public_key(public_key_pem)
    rsa = PKCS1_OAEP.new(pub)
    enc_aes_key = rsa.encrypt(aes_key)
    t3 = perf_counter()
    t_rsa_enc = t3 - t2

    timing = EncTiming(
        t_aes_enc=t_aes_enc,
        t_rsa_enc=t_rsa_enc,
        t_total_enc=(t3 - t0)
    )

    payload = {
        "scheme": "HYBRID_RSA_OAEP_AES_GCM",
        "rsa_bits": pub.size_in_bits(),
        "aes_bits": aes_bits,
        # b64 so it's JSON-safe
        "ciphertext": b64e(ciphertext),
        "nonce":      b64e(nonce),
        "tag":        b64e(tag),
        "enc_aes_key": b64e(enc_aes_key),
    }
    return payload, timing

# ---------- Hybrid Decrypt ----------
def hybrid_decrypt(payload: dict, private_key_pem: bytes) -> tuple[bytes, DecTiming]:
    """
    Decrypt AES key with RSA-OAEP; then AES-GCM to recover plaintext.
    Returns:
      plaintext (bytes) and DecTiming
    """
    # Parse b64
    ciphertext = b64d(payload["ciphertext"])
    nonce      = b64d(payload["nonce"])
    tag        = b64d(payload["tag"])
    enc_aes_key= b64d(payload["enc_aes_key"])

    # RSA-OAEP (unwrap AES key)
    t0 = perf_counter()
    priv = load_private_key(private_key_pem)
    rsa = PKCS1_OAEP.new(priv)
    aes_key = rsa.decrypt(enc_aes_key)
    t1 = perf_counter()
    t_rsa_dec = t1 - t0

    # AES-GCM decrypt + verify tag
    t2 = perf_counter()
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    t3 = perf_counter()
    t_aes_dec = t3 - t2

    timing = DecTiming(
        t_rsa_dec=t_rsa_dec,
        t_aes_dec=t_aes_dec,
        t_total_dec=(t3 - t0)
    )
    return plaintext, timing

# ---------- Demo & Timing ----------
if __name__ == "__main__":
    # 1) Generate RSA keys (gunakan 3072 bit sesuai best practice saat ini untuk skripsi)
    pub_pem, priv_pem = generate_rsa_keys(bits=3072)

    # 2) Plaintext uji (pesan teks)
    message = "Pengujian hybrid RSA–AES untuk skripsi. IDPEL: 512345678901"
    print("Plaintext:", message)

    # 3) ENKRIPSI
    payload, enc_t = hybrid_encrypt(message.encode("utf-8"), pub_pem, aes_bits=128)
    print("\n=== ENKRIPSI (AES-GCM + RSA-OAEP) ===")
    print(f"AES Encrypt time : {enc_t.t_aes_enc:.6f} s")
    print(f"RSA Encrypt time : {enc_t.t_rsa_enc:.6f} s")
    print(f"Total Encrypt    : {enc_t.t_total_enc:.6f} s")
    print("Payload (JSON, ringkas):")
    print(json.dumps({k: (payload[k][:50] + "...") if isinstance(payload[k], str) and len(payload[k]) > 60 else payload[k]
                      for k in payload}, indent=2))

    # 4) DEKRIPSI
    plaintext_out, dec_t = hybrid_decrypt(payload, priv_pem)
    print("\n=== DEKRIPSI (RSA-OAEP + AES-GCM) ===")
    print(f"RSA Decrypt time : {dec_t.t_rsa_dec:.6f} s")
    print(f"AES Decrypt time : {dec_t.t_aes_dec:.6f} s")
    print(f"Total Decrypt    : {dec_t.t_total_dec:.6f} s")
    print("Plaintext hasil  :", plaintext_out.decode("utf-8"))
