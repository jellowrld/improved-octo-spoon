import os
import subprocess

print("[OCTOSPOON] Building evasion.sys...")

os.makedirs("drivers", exist_ok=True)

if not os.path.exists("drivers/evasion.c"):
    print("[!] evasion.c is missing!")
    # Create a placeholder or exit
    exit(1)

cmd = [
    "cl", "/D_AMD64_", "/kernel", "/W3", "/O2", "/GS-", "/Zc:wchar_t-",
    "drivers/evasion.c",
    "/link", "/SUBSYSTEM:NATIVE", "/DRIVER", "/OUT:drivers/evasion.sys",
    "/ENTRY:DriverEntry", "/DEBUG"
]

result = subprocess.run(cmd, capture_output=True, text=True, shell=False)

if result.returncode == 0:
    print("[OCTOSPOON] evasion.sys built successfully!")
else:
    print("[!] Build failed!")
    print("STDOUT:", result.stdout)
    print("STDERR:", result.stderr)
    print("\nMake sure you're in Developer Command Prompt + WDK installed.")
