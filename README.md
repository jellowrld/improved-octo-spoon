# OCTOSPOON v1.0

	16 ADVANCED INJECTION TECHNIQUES | ONE SPOON TO RULE THEM ALL


A powerful, modern **Windows DLL/EXE injector** with a clean PyQt6 GUI. Supports **16 different injection methods** ranging from classic to highly stealthy techniques.

## Features

- **Modern Dark GUI** with process browser, payload selector, and real-time logging
- **16 Injection Methods**:
  1. Standard (CreateRemoteThread + LoadLibrary)
  2. APC (QueueUserAPC)
  3. Early Bird APC
  4. Thread Hijack
  5. Reflective DLL
  6. Manual Map
  7. Process Hollowing (RunPE)
  8. Thread Pool
  9. Kernel Driver
  10. AtomBombing
  11. SetWindowsHookEx
  12. PowerLoader
  13. Section Mapping
  14. NtCreateThreadEx
  15. RtlCreateUserThread
  16. NtTestAlert (APC variant)

- Built-in support for both DLL and EXE payloads
- Real-time process list via psutil
- Runs on x64 Windows only

## Installation & Usage

1. **Clone the repository**
   git clone https://github.com/jellowrld/improved-octo-spoon.git
   cd improved-octo-spoon

2. **Install dependencies**
   pip install -r requirements.txt

3. **Run the GUI (as Administrator)**
   python octospoon_gui.py

4. **(Optional) Build Standalone EXE**
   .\build_gui.bat

5. **(Optional) Kernel Driver**
   Enable test signing: bcdedit /set testsigning on + restart
   Build driver: python build_driver.py
