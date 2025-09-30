# hybrid_sim_local.py
# Simulasi defensif hybrid RSA + AES-GCM di mesin lokal
# Menunjukkan enkripsi/dekripsi normal, simulasi tamper, pengukuran waktu & memori ringan, hasil tersimpan CSV.
import time
import tracemalloc
import csv
import binascii
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

def gen_rsa_bits(bits=2048):
    key = RSA.generate(bits)
    pub = key.publickey()
    return key, pub

def rsa_encrypt(pubkey, data_bytes):
    cipher = PKCS1_OAEP.new(pubkey)
    return cipher.encrypt(data_bytes)

def rsa_decrypt(privkey, ciphertext):
    cipher = PKCS1_OAEP.new(privkey)
    return cipher.decrypt(ciphertext)

def aes_gcm_encrypt(aes_key, plaintext_bytes):
    nonce = get_random_bytes(12)  # recommended 12 bytes for GCM
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
    return nonce, ciphertext, tag

def aes_gcm_decrypt(aes_key, nonce, ciphertext, tag):
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def hexx(b):
    return binascii.hexlify(b).decode()

def measure_mem_time(func, *args, **kwargs):
    """Return (result, time_sec, mem_peak_kb)"""
    tracemalloc.start()
    t0 = time.perf_counter()
    res = func(*args, **kwargs)
    t1 = time.perf_counter()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    # peak in bytes -> convert to KB
    return res, (t1 - t0), (peak / 1024.0)

def save_results_csv(filename, rows, header=None):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if header:
            writer.writerow(header)
        writer.writerows(rows)

def simulate_and_record():
    results = []
    header = ["scenario","payload_bytes","rsa_key_bits","aes_key_len_bytes","op","time_sec","mem_peak_kb","note"]
    # 1. Generate RSA keys (measure time/mem)
    (rsa_priv, rsa_pub), (t_rsa_gen, mem_rsa) = None, (None, None)
    tracemalloc.start()
    t0 = time.perf_counter()
    rsa_priv, rsa_pub = gen_rsa_bits(2048)
    t1 = time.perf_counter()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    t_rsa_gen = t1 - t0
    mem_rsa = peak / 1024.0
    results.append(["rsa_keygen", 0, 2048, 0, "gen", f"{t_rsa_gen:.6f}", f"{mem_rsa:.2f}", "RSA keygen"])
    
    # 2. Generate AES session key
    aes_key = get_random_bytes(16)  # AES-128
    results.append(["aes_keygen", 0, 2048, len(aes_key), "gen", "0.000000", "0.00", "AES session key generated"])

    # Payload examples: small and medium (you can change/add)
    payloads = [
        b"Pesan uji hybrid cryptography. Data palsu untuk skripsi.",
        b"A" * 1024,  # 1 KB
        b"B" * 10 * 1024  # 10 KB
    ]

    for p in payloads:
        payload_len = len(p)
        # AES encrypt (measure)
        (nonce, ciphertext, tag), t_aes_enc, mem_aes_enc = measure_mem_time(lambda k,pl: aes_gcm_encrypt(k,pl), aes_key, p)
        results.append(["aes_gcm_encrypt", payload_len, 2048, len(aes_key), "encrypt", f"{t_aes_enc:.6f}", f"{mem_aes_enc:.2f}", "AES-GCM encrypt payload"])
        # RSA encrypt AES key (measure)
        enc_aes_key, t_rsa_enc, mem_rsa_enc = measure_mem_time(lambda pub, d: rsa_encrypt(pub, d), rsa_pub, aes_key)
        results.append(["rsa_encrypt_aes_key", payload_len, 2048, len(aes_key), "encrypt", f"{t_rsa_enc:.6f}", f"{mem_rsa_enc:.2f}", "RSA encrypt AES key"])
        # RSA decrypt AES key (measure)
        dec_aes_key, t_rsa_dec, mem_rsa_dec = measure_mem_time(lambda priv, d: rsa_decrypt(priv, d), rsa_priv, enc_aes_key)
        results.append(["rsa_decrypt_aes_key", payload_len, 2048, len(aes_key), "decrypt", f"{t_rsa_dec:.6f}", f"{mem_rsa_dec:.2f}", "RSA decrypt AES key"])
        # AES decrypt normal (measure)
        try:
            recovered, t_aes_dec, mem_aes_dec = measure_mem_time(lambda k,n,c,tg: aes_gcm_decrypt(k,n,c,tg), dec_aes_key, nonce, ciphertext, tag)
            ok = (recovered == p)
            note = "ok" if ok else "mismatch"
            results.append(["aes_gcm_decrypt", payload_len, 2048, len(aes_key), "decrypt", f"{t_aes_dec:.6f}", f"{mem_aes_dec:.2f}", note])
        except Exception as e:
            results.append(["aes_gcm_decrypt", payload_len, 2048, len(aes_key), "decrypt", "error", "error", f"Exception:{e}"])
        
        # Record hex snippets if small payload
        if payload_len <= 64:
            print("PAYLOAD (utf8):", p.decode(errors="ignore"))
            print("CIPHERTEXT (hex):", hexx(ciphertext))
            print("TAG (hex):", hexx(tag))
            print("NONCE (hex):", hexx(nonce))
            print("---")

        # SIMULASI TAMPER: flip 1 bit in ciphertext
        tampered = bytearray(ciphertext)
        if len(tampered) > 0:
            tampered[0] ^= 0x01
            tampered = bytes(tampered)
            # Try decrypt tampered
            try:
                _ = aes_gcm_decrypt(dec_aes_key, nonce, tampered, tag)
                # If no exception, unexpected success
                results.append(["tampered_decrypt", payload_len, 2048, len(aes_key), "decrypt", "unexpected_success", "0.00", "Tampered ciphertext decrypted (UNEXPECTED)"])
            except Exception as e:
                results.append(["tampered_decrypt", payload_len, 2048, len(aes_key), "decrypt", "failed_as_expected", "0.00", f"Exception:{str(e)}"])
        else:
            results.append(["tampered_decrypt", payload_len, 2048, len(aes_key), "decrypt", "skipped", "0.00", "ciphertext empty"])

    # Save CSV
    save_results_csv("hybrid_sim_results.csv", results, header=header)
    print("Simulation complete. Results saved to hybrid_sim_results.csv")
    return results

if __name__ == "__main__":
    simulate_and_record()
