# Octo Spoon v5.0

**10 Injection Methods – All Working**

## Requirements

| Tool | Install |
|------|--------|
| **Python 3.9+** | https://python.org |
| **Visual Studio 2022** | Community OK |
| **Windows SDK** | During VS install |
| **Windows Driver Kit (WDK)** | https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk |
| **Test Signing** | `bcdedit /set testsigning on` |

---

## FULL SETUP (Step-by-Step)

```powershell
# 1. Install Visual Studio 2022
#    → Desktop development with C++
#    → Windows 10/11 SDK
#    → Windows Driver Kit (WDK)

# 2. Enable Test Signing
bcdedit /set testsigning on
Restart-Computer

# 3. Install Python deps
pip install -r requirements.txt

# 4. Build driver
python build.py

# 5. Run injector
python injector_v5.py
