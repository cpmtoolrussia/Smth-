#!/usr/bin/env python3
"""
CPM1 ES3 ReKey

Перешифровка .es3-файлов CPM1: ключ донора → ключ цели.

Использование:
    python3 es3_rekey.py
    python3 es3_rekey.py -i es3.zip -o es3_modified.zip

Зависимости:
    pip install requests cryptography
"""

import argparse
import base64
import sys
import tempfile
import zipfile
from pathlib import Path

try:
    import requests
except ImportError:
    print("!!! Установи requests:  pip install requests")
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


# ═════════════════════════════════════════════════════════════
#  КОНСТАНТЫ
# ═════════════════════════════════════════════════════════════

CPM1_API_KEY = "AIzaSyBW1ZbMiUeDZHYUO2bY8Bfnf5rRgrQGPTM"
ES3_FILENAME = "SaveFile.es3"


# ═════════════════════════════════════════════════════════════
#  ES3 KEY FETCH
# ═════════════════════════════════════════════════════════════

def get_es3_key(email: str, password: str) -> str:
    """Логинится в Firebase CPM1, возвращает ES3-ключ (6 символов)."""
    url = f"https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key={CPM1_API_KEY}"
    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True,
        "clientType": "CLIENT_TYPE_ANDROID",
    }
    try:
        r = requests.post(url, json=payload, timeout=30)
    except Exception as e:
        raise RuntimeError(f"Network error: {e}")

    if r.status_code != 200:
        raise RuntimeError(f"Auth failed (HTTP {r.status_code})")

    try:
        res = r.json()
    except Exception:
        raise RuntimeError("Invalid JSON from Firebase")

    local_id = res.get("localId")
    if not local_id:
        err = res.get("error", {}).get("message", "unknown")
        raise RuntimeError(f"No localId ({err})")

    account_key = local_id[:3]

    n = ES3_FILENAME.split(".")[0]
    pad_len = len(n) % 4
    if pad_len:
        n += "=" * (4 - pad_len)
    try:
        decoded = base64.b64decode(n)
        file_key = decoded[:3].decode("utf-8", errors="replace")
    except Exception:
        raise RuntimeError("Invalid filename format")

    return f"{file_key}{account_key}"


# ═════════════════════════════════════════════════════════════
#  AES (через cryptography)
# ═════════════════════════════════════════════════════════════

def key_to_16(key_str: str) -> bytes:
    b = key_str.encode("utf-8")
    return (b + b"\x00" * 16)[:16]


def _decrypt_aes_cbc(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(data) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _decrypt_aes_ecb(data: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    padded = decryptor.update(data) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def decrypt_es3(data: bytes, key: bytes) -> bytes:
    """Пробуем 3 варианта AES, как делает ES3."""
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography не установлен")
    # 1) CBC + нулевой IV
    try:
        return _decrypt_aes_cbc(data, key, b"\x00" * 16)
    except Exception:
        pass
    # 2) CBC + IV в первых 16 байтах
    try:
        return _decrypt_aes_cbc(data[16:], key, data[:16])
    except Exception:
        pass
    # 3) ECB
    try:
        return _decrypt_aes_ecb(data, key)
    except Exception:
        pass
    raise ValueError("Не удалось расшифровать (CBC/0, CBC/iv, ECB — все провалились)")


def encrypt_es3(data: bytes, key: bytes) -> bytes:
    """Шифруем как ES3: AES-CBC + нулевой IV + PKCS7."""
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16))
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()


# ═════════════════════════════════════════════════════════════
#  ОБРАБОТКА ZIP
# ═════════════════════════════════════════════════════════════

def process_zip(zip_in: Path, zip_out: Path, donor_key: str, target_key: str) -> bool:
    dk = key_to_16(donor_key)
    tk = key_to_16(target_key)
    print(f"  donor  key = {donor_key!r} → {dk.hex()}")
    print(f"  target key = {target_key!r} → {tk.hex()}")

    with tempfile.TemporaryDirectory() as tmp_s:
        tmp = Path(tmp_s)

        print(f"\n[1] Распаковка {zip_in.name}...")
        with zipfile.ZipFile(zip_in, "r") as z:
            z.extractall(tmp)

        es3_files = sorted(tmp.rglob("*.es3"))
        print(f"  Найдено .es3: {len(es3_files)}")

        if not es3_files:
            print("!!! В архиве нет .es3 файлов.")
            return False

        print(f"\n[2] Перешифровка {len(es3_files)} файлов...")
        ok, fail = 0, 0
        for i, f in enumerate(es3_files, 1):
            try:
                raw = f.read_bytes()
                if len(raw) % 16 != 0:
                    print(f"  [{i}/{len(es3_files)}] ❌ {f.name}: размер {len(raw)} не кратен 16")
                    fail += 1
                    continue
                plain = decrypt_es3(raw, dk)
                enc = encrypt_es3(plain, tk)
                f.write_bytes(enc)
                ok += 1
                if i <= 3 or i % 25 == 0 or i == len(es3_files):
                    preview = plain[:40].decode("utf-8", "replace").replace("\n", " ")
                    print(f"  [{i}/{len(es3_files)}] ✅ {f.name}  ({len(raw)}→{len(enc)})  {preview!r}")
            except Exception as e:
                print(f"  [{i}/{len(es3_files)}] ❌ {f.name}: {str(e)[:80]}")
                fail += 1

        print(f"\n  Итог: ✅ {ok}  ❌ {fail}")
        if ok == 0:
            print("!!! Ни один файл не перешифрован — ключи неверные или формат не тот.")
            return False

        print(f"\n[3] Сборка {zip_out.name}...")
        zip_out.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zip_out, "w", zipfile.ZIP_DEFLATED) as z:
            for f in tmp.rglob("*"):
                if f.is_file():
                    z.write(f, f.relative_to(tmp))
        size = zip_out.stat().st_size
        print(f"  ✅ {zip_out.resolve()} ({size/1024:.1f} KB)")
        return True


# ═════════════════════════════════════════════════════════════
#  MAIN
# ═════════════════════════════════════════════════════════════

def main():
    if not HAS_CRYPTO:
        print("!!! Установи cryptography:  pip install cryptography")
        sys.exit(1)

    ap = argparse.ArgumentParser(
        description="CPM1 ES3 ReKey — перешифровка .es3 zip-архива"
    )
    ap.add_argument("-i", "--input", default="es3.zip",
                    help="Входной .zip с ES3-файлами донора (по умолчанию: es3.zip)")
    ap.add_argument("-o", "--output", default="es3_modified.zip",
                    help="Выходной .zip (по умолчанию: es3_modified.zip)")
    args = ap.parse_args()

    zip_in = Path(args.input)
    zip_out = Path(args.output)

    if not zip_in.exists():
        print(f"!!! Нет файла: {zip_in}")
        print(f"    Положи {zip_in.name} рядом с es3_rekey.py или укажи -i путь")
        sys.exit(1)

    print("═" * 60)
    print("  CPM1 ES3 REKEY")
    print("═" * 60)
    print(f"  input:  {zip_in}")
    print(f"  output: {zip_out}")

    print("\n─── ДОНОР (CPM1) ───")
    d_email = input("Email: ").strip()
    d_pass = input("Password: ").strip()

    print("\n─── ЦЕЛЬ (CPM1) ───")
    t_email = input("Email: ").strip()
    t_pass = input("Password: ").strip()

    print("\n[*] Получаю ES3-ключи...")
    try:
        donor_key = get_es3_key(d_email, d_pass)
        print(f"  ✅ donor  key: {donor_key}")
    except Exception as e:
        print(f"  ❌ donor: {e}")
        sys.exit(1)

    try:
        target_key = get_es3_key(t_email, t_pass)
        print(f"  ✅ target key: {target_key}")
    except Exception as e:
        print(f"  ❌ target: {e}")
        sys.exit(1)

    print()
    ok = process_zip(zip_in, zip_out, donor_key, target_key)

    if ok:
        print("\n" + "═" * 60)
        print("  ГОТОВО")
        print("═" * 60)
        print(f"\n  Файл: {zip_out.resolve()}")
        print(f"\n  Распакуй его в папку игры (поверх старых .es3):")
        print(f"  /storage/emulated/0/Android/data/com.olzhas.carparking.multyplayer/files/")


if __name__ == "__main__":
    main()