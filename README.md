# OCTOSPOON v1.0

	10 INJECTION METHODS | ONE SPOON TO RULE THEM ALL

## Methods
1. Standard  
2. APC  
3. Early Bird  
4. Thread Hijack  
5. Reflective  
6. Manual Map  
7. Process Hollowing  
8. Thread Pool  
9. **Kernel Driver (SSDT)**  
10. **AtomBombing**

## Setup
```powershell
bcdedit /set testsigning on
Restart-Computer

pip install -r requirements.txt
python build_driver.py
python octospoon.py
