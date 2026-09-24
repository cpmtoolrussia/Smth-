import base64
import asyncio
import aiohttp

CPM1_API_KEY = "AIzaSyBW1ZbMiUeDZHYUO2bY8Bfnf5rRgrQGPTM"
CPM2_API_KEY = "AIzaSyCQDz9rgjgmvmFkvVfmvr2-7fT4tfrzRRQ"

async def main():
    email = input("Email: ").strip()
    password = input("Password: ").strip()
    filename = input("ES3 Filename: ").strip()
    ver = input("Version [1/2] (Default 1): ").strip()
    
    api_key = CPM2_API_KEY if ver == "2" else CPM1_API_KEY
    url = f"https://www.googleapis.com/identitytoolkit/v3/relyingparty/verifyPassword?key={api_key}"
    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True,
        "clientType": "CLIENT_TYPE_ANDROID",
    }
    
    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=payload) as resp:
            if resp.status != 200:
                print("[-] Authentication failed.")
                return
            res = await resp.json()
            local_id = res.get("localId")
            if not local_id:
                print("[-] Failed to get local ID.")
                return
            
            account_key = local_id[:3]
            
            try:
                n = filename.split(".")[0]
                pad = len(n) % 4
                if pad:
                    n += "=" * (4 - pad)
                decoded = base64.b64decode(n)
                file_key = decoded[:3].decode("utf-8", errors="replace")
            except Exception:
                print("[-] Invalid filename format.")
                return
                
            full_key = f"{file_key}{account_key}"
            print(f"\n[+] ES3 Key: {full_key}")

if __name__ == "__main__":
    asyncio.run(main())