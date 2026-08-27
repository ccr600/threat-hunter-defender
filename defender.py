import re, pathlib, hashlib, datetime

BLOCKED_FILE = "blocked_ips.txt"
REPORT_FILE = "reporte_incidente.txt"

def get_sha256(file_path):
    h = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def defender(log_file):
    print(f"[DEFENDER] Analizando {log_file}")
    sha = get_sha256(log_file)
    text = pathlib.Path(log_file).read_text(errors='ignore')
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    maliciosas = [ip for ip in set(ips) if ip.startswith("10.0.0.") or ip.startswith("192.168.")]

    with open(BLOCKED_FILE, 'w') as f:
        for ip in maliciosas:
            f.write(ip + "\n")

    with open(REPORT_FILE, 'w') as f:
        f.write(f"REPORTE DE INCIDENTE - {datetime.datetime.now()}\n")
        f.write(f"Archivo: {log_file}\n")
        f.write(f"SHA256: {sha}\n")
        f.write(f"IPs Bloqueadas: {', '.join(maliciosas)}\n")
        f.write(f"Accion: Bloqueo preventivo aplicado\n")

    print(f"[+] IPs bloqueadas guardadas en {BLOCKED_FILE}")
    print(f"[+] Reporte generado en {REPORT_FILE}")
        # Hash del reporte para que sea único cada ejecución
    import hashlib
    with open(REPORT_FILE, 'rb') as rf:
        sha_reporte = hashlib.sha256(rf.read()).hexdigest()
    
    print(f"[+] SHA256 Evidencia: {sha}")
    print(f"[+] SHA256 Reporte UNICO: {sha_reporte}")
    print("[OK] DEFENSA COMPLETADA")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Uso: python3 defender.py <archivo.log>")
    else:
        defender(sys.argv[1])
