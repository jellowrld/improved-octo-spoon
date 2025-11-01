import os
import subprocess

print("Building evasion.sys...")

os.makedirs("drivers", exist_ok=True)

# Write evasion.c if not exists
if not os.path.exists("drivers/evasion.c"):
    with open("drivers/evasion.c", "w") as f:
        f.write(open("drivers/evasion.c").read())  # Self-replace

# Compile with cl.exe (Visual Studio)
cmd = [
    "cl", "/D_AMD64_", "/driver", "/W3", "/O2",
    "drivers/evasion.c",
    "/link", "/SUBSYSTEM:NATIVE", "/DRIVER", "/OUT:drivers/evasion.sys"
]

result = subprocess.run(cmd, capture_output=True, text=True)

if result.returncode == 0:
    print("evasion.sys built successfully!")
else:
    print("Build FAILED.")
    print(result.stderr)
    print("\nInstall: Visual Studio + Windows SDK + WDK")
