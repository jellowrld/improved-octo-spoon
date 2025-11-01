import os
import subprocess

print("[OCTOSPOON] Building evasion.sys...")

os.makedirs("drivers", exist_ok=True)

# Ensure evasion.c exists
if not os.path.exists("drivers/evasion.c"):
    print("[!] evasion.c missing! Creating...")
    with open("drivers/evasion.c", "w") as f:
        f.write(open("drivers/evasion.c").read())  # Self-replace if needed

cmd = [
    "cl", "/D_AMD64_", "/driver", "/W3", "/O2",
    "drivers/evasion.c",
    "/link", "/SUBSYSTEM:NATIVE", "/DRIVER", "/OUT:drivers/evasion.sys"
]

result = subprocess.run(cmd, capture_output=True, text=True)

if result.returncode == 0:
    print("[OCTOSPOON] evasion.sys built!")
else:
    print("[!] Build failed. Install VS + WDK")
    print(result.stderr)