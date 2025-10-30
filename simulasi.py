# ==========================================================
# SIMULASI ENKRIPSI PESAN TEKS MENGGUNAKAN AES-128 (GCM)
# dengan pengukuran waktu menggunakan time.perf_counter()
# ==========================================================

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from time import perf_counter

# 1️⃣ Masukkan pesan teks
plaintext = "Data pelanggan PLN dengan IDPEL 512345678901"  # contoh pesan teks
print("Plaintext:", plaintext)

# 2️⃣ Buat kunci AES 128-bit (16 byte)
aes_key = get_random_bytes(16)  # 16 byte = 128 bit

# 3️⃣ Mulai pengukuran waktu enkripsi
t0 = perf_counter()

# AES GCM mode memberikan confidentiality + integrity (tag)
cipher = AES.new(aes_key, AES.MODE_GCM)
ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
nonce = cipher.nonce

t1 = perf_counter()  # waktu selesai
elapsed_time = t1 - t0

# 4️⃣ Tampilkan hasil
print("\n=== HASIL ENKRIPSI AES-128 ===")
print("Kunci AES (hex):", aes_key.hex())
print("Nonce:", nonce.hex())
print("Tag:", tag.hex())
print("Ciphertext:", ciphertext.hex())
print(f"\nWaktu Enkripsi: {elapsed_time:.8f} detik")
