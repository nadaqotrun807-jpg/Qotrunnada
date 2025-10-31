# ==========================================================
# SIMULASI: ENKRIPSI KUNCI AES DENGAN RSA (OAEP) + TIMING
# ==========================================================
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from time import perf_counter

# 1) Siapkan kunci AES (128-bit) dan pasangan kunci RSA
aes_key = get_random_bytes(16)  # 16 byte = 128-bit
rsa_bits = 3072                  # bisa 2048/3072/4096
rsa_key = RSA.generate(rsa_bits)
pub_key = rsa_key.public_key()
priv_key = rsa_key

# 2) Enkripsi kunci AES menggunakan RSA-OAEP (PUBLIC KEY)
rsa_enc = PKCS1_OAEP.new(pub_key)
t0 = perf_counter()
enc_aes_key = rsa_enc.encrypt(aes_key)
t1 = perf_counter()
t_rsa_encrypt = t1 - t0

# 3) Dekripsi kunci AES menggunakan RSA-OAEP (PRIVATE KEY) untuk verifikasi
rsa_dec = PKCS1_OAEP.new(priv_key)
t2 = perf_counter()
dec_aes_key = rsa_dec.decrypt(enc_aes_key)
t3 = perf_counter()
t_rsa_decrypt = t3 - t2

# 4) Verifikasi kesamaan kunci & tampilkan hasil
ok = (dec_aes_key == aes_key)

print("=== SIMULASI RSA-OAEP: ENKRIPSI KUNCI AES ===")
print(f"RSA size        : {rsa_bits} bit")
print(f"AES key (hex)   : {aes_key.hex()}")
print(f"enc_aes_key len : {len(enc_aes_key)} byte")
print(f"Match after dec?: {ok}")
print(f"\nWaktu RSA Encrypt kunci AES : {t_rsa_encrypt:.6f} detik")
print(f"Waktu RSA Decrypt kunci AES : {t_rsa_decrypt:.6f} detik")
