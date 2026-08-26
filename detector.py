import re, sys, ipaddress, pathlib, hashlib

SUSPICIOUS_PATTERNS = [
    r"mimikatz", r"powershell.*-enc", r"Invoke-Mimikatz",
    r"nmap.*-sS", r"sqlmap", r"hydra", r"hashcat",
    r"\b(?:\d{1,3}\.){3}\d{1,3}:4444\b", r"cmd\.exe.*/c"
]

def get_sha256(file_path):
    h = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def scan_log(file_path):
    print(f"[+] Escaneando: {file_path}")
    sha = get_sha256(file_path)
    print(f"[+] SHA256: {sha}")
    hits = []
    text = pathlib.Path(file_path).read_text(errors='ignore')
    for pattern in SUSPICIOUS_PATTERNS:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            hits.append((pattern, m.group(0)[:80]))
    for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        try:
            if ipaddress.ip_address(ip).is_private and ip!= "127.0.0.1":
                hits.append(("IP-PRIVADA-SOSPECHOSA", ip))
        except:
            pass
    if hits:
        print("\n[!] AMENAZAS DETECTADAS:")
        for p, val in hits:
            print(f" - {p} => {val}")
    else:
        print("[OK] Limpio - No se detectaron amenazas")
    print(f"\n[EVIDENCIA] SHA256 del archivo: {sha}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python3 detector.py <archivo.log>")
    else:
        scan_log(sys.argv[1])
