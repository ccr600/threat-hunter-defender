import sys, subprocess
print("=== THREAT-HUNTER-DEFENDER ===")
log = sys.argv[1] if len(sys.argv)>1 else "ataque_simulado.log"
subprocess.run(["python3", "detector.py", log])
subprocess.run(["python3", "defender.py", log])
print("\n[FIN] Proceso completo con evidencia SHA256")
