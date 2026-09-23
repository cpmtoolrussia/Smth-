#!/usr/bin/env python3
"""
lookup_check.py — получить email и публичные данные аккаунтов CPM по localID.

Использует публичный Firebase Web API key (тот же, что в боте, FK).
Не требует Admin SDK, не сбрасывает пароли, ничего не меняет на аккаунте.
Только чтение: accounts:lookup.

Использование:
    python3 lookup_check.py UID1 UID2 UID3 ...
    python3 lookup_check.py -f uids.txt
    echo "UID1\nUID2" | python3 lookup_check.py -

Формат uids.txt: один localID на строку, # — комментарий.
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import List, Dict, Any

import aiohttp

# Тот же ключ, что в CPM1Tool_byAlexGG.py
FK = "AIzaSyAe_aOVT1gSfmHKBrorFvX4fRwN5nODXVA"

LOOKUP_URL = f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={FK}"

# Firebase accounts:lookup принимает максимум 100 localId за раз
BATCH_SIZE = 100

HEADERS = {
    "Accept": "*/*",
    "Accept-Encoding": "gzip",
    "Content-Type": "application/json",
    "User-Agent": "UnityPlayer/2022.3.62f2 (UnityWebRequest/1.0, libcurl/8.10.1-DEV)",
    "X-Unity-Version": "2022.3.62f2",
}

# ─── цвета для вывода ───
class C:
    R = "\033[0m"
    B = "\033[1m"
    DIM = "\033[2m"
    GRN = "\033[92m"
    YEL = "\033[93m"
    RED = "\033[91m"
    CYA = "\033[96m"


def log(msg: str):
    print(msg, flush=True)


async def lookup_batch(session: aiohttp.ClientSession,
                       uids: List[str]) -> Dict[str, Any]:
    """Один запрос accounts:lookup на пачку UID."""
    payload = {"localId": uids}
    try:
        async with session.post(LOOKUP_URL, json=payload, headers=HEADERS) as r:
            text = await r.text()
            try:
                data = json.loads(text)
            except Exception:
                return {"_error": f"bad json ({r.status}): {text[:200]}"}
            if r.status != 200:
                err = data.get("error", {})
                return {
                    "_error": f"{r.status}: {err.get('message', text[:200])}",
                    "_raw": data,
                }
            return data
    except Exception as e:
        return {"_error": f"network: {e}"}


def fmt_user(u: Dict[str, Any]) -> str:
    uid = u.get("localId", "?")
    email = u.get("email", "—")
    verified = u.get("emailVerified", False)
    name = u.get("displayName", "")
    created = u.get("createdAt")
    last = u.get("lastLoginAt")

    def _ts(ms):
        if not ms:
            return "—"
        try:
            from datetime import datetime
            return datetime.fromtimestamp(int(ms) / 1000).strftime("%Y-%m-%d %H:%M")
        except Exception:
            return str(ms)

    vmark = f"{C.GRN}✔{C.R}" if verified else f"{C.YEL}✗{C.R}"
    line = (
        f"  {C.CYA}{uid}{C.R}\n"
        f"    email:     {C.B}{email}{C.R}  {vmark}\n"
    )
    if name:
        line += f"    name:      {name}\n"
    line += (
        f"    created:   {_ts(created)}\n"
        f"    last login:{_ts(last)}\n"
    )
    return line


async def run(uids: List[str], out_path: str | None):
    uids = [u.strip() for u in uids if u.strip() and not u.strip().startswith("#")]
    if not uids:
        log(f"{C.RED}✗ Нет UID для проверки.{C.R}")
        return 1

    log(f"{C.B}════════════════════════════════════════{C.R}")
    log(f"{C.B}  Firebase accounts:lookup{C.R}")
    log(f"  Ключ: {FK[:20]}...{FK[-8:]}")
    log(f"  UID:  {len(uids)}")
    log(f"{C.B}════════════════════════════════════════{C.R}")

    found: List[Dict[str, Any]] = []
    not_found: List[str] = []

    timeout = aiohttp.ClientTimeout(total=30)
    connector = aiohttp.TCPConnector(ssl=False, limit=4)
    async with aiohttp.ClientSession(timeout=timeout,
                                     connector=connector) as session:
        for i in range(0, len(uids), BATCH_SIZE):
            chunk = uids[i:i + BATCH_SIZE]
            log(f"{C.DIM}→ запрос {i+1}..{i+len(chunk)} из {len(uids)}{C.R}")
            data = await lookup_batch(session, chunk)

            if "_error" in data:
                log(f"{C.RED}✗ ошибка: {data['_error']}{C.R}")
                if "_raw" in data:
                    log(f"  raw: {json.dumps(data['_raw'], ensure_ascii=False)[:400]}")
                continue

            users = data.get("users", [])
            returned_ids = {u.get("localId") for u in users}

            for u in users:
                found.append(u)
                print(fmt_user(u))

            for uid in chunk:
                if uid not in returned_ids:
                    not_found.append(uid)
                    log(f"  {C.YEL}∅{C.R} {C.CYA}{uid}{C.R} — не найден")

    log(f"{C.B}────────────────────────────────────────{C.R}")
    log(f"  {C.GRN}✔ найдено:      {len(found)}{C.R}")
    log(f"  {C.YEL}∅ не найдено:   {len(not_found)}{C.R}")
    if not_found:
        log(f"    {C.DIM}{', '.join(not_found[:20])}"
            + (" ..." if len(not_found) > 20 else "") + f"{C.R}")
    log(f"{C.B}════════════════════════════════════════{C.R}")

    if out_path:
        out = Path(out_path)
        payload = {
            "found": found,
            "not_found": not_found,
            "total_requested": len(uids),
        }
        out.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                       encoding="utf-8")
        log(f"{C.GRN}✔ JSON сохранён: {out}{C.R}")

    return 0


def parse_args():
    p = argparse.ArgumentParser(
        description="Получить email и публичные данные CPM-аккаунтов по localID "
                    "через Firebase accounts:lookup (только чтение)."
    )
    p.add_argument("uids", nargs="*", default=[],
                   help="Список localID. '-' означает 'читать из stdin'.")
    p.add_argument("-f", "--file", help="Файл со списком localID (по одному на строку).")
    p.add_argument("-o", "--out", help="Сохранить результат в JSON.")
    return p.parse_args()


def main():
    args = parse_args()
    uids: List[str] = list(args.uids)

    if args.file:
        path = Path(args.file)
        if not path.exists():
            log(f"{C.RED}✗ Файл не найден: {path}{C.R}")
            return 1
        uids += path.read_text(encoding="utf-8").splitlines()

    if "-" in uids:
        uids = [u for u in uids if u != "-"]
        uids += sys.stdin.read().splitlines()

    if not uids:
        log(f"{C.YEL}Использование:{C.R}")
        log(f"  python3 lookup_check.py UID1 UID2 UID3")
        log(f"  python3 lookup_check.py -f uids.txt -o result.json")
        log(f"  echo 'UID1\\nUID2' | python3 lookup_check.py -")
        return 1

    try:
        return asyncio.run(run(uids, args.out))
    except KeyboardInterrupt:
        log(f"\n{C.YEL}Прервано.{C.R}")
        return 130


if __name__ == "__main__":
    sys.exit(main())