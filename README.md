# HashBackup

**HashBackup** is a Python tool to verify that your files are properly backed up by comparing source and destination contents using SHA-256 hashes. It works with local folders or remote destinations over SSH/SFTP, supports partial or full file hashing, and can generate reports in HTML, CSV, or JSON.  

**Versions & Features:**  
- **R1 (`hashbackup_R1.py`)** – Manual comparison with Norton-Commander–style folder browser for local folders.  
- **R2 (`hashbackup_R2.py`)** – Adds workflow menu for guided operations.  
- **R3 (`hashbackup_R3.py`)** – Adds default options for faster, simpler usage, enhanced interactive workflow, improved logging, and refined export options (HTML, CSV, JSON).  
- **R4 (`hashbackup_R4.py`)** – Advanced interactive menu, full Norton-Commander–style browsing, and improved SSH/backup handling.  
- **R5 (`hashbackup_R5.py`)** – Extends Norton-Commander style to destination folders (if local).

**Dependencies:** Python 3.8+; optional `paramiko` for SSH functionality (`pip install paramiko`).  

**Usage Examples:**  
```bash
# Interactive mode (manual folder selection)
python3 hashbackup_R1.py /Source-Path/ /Destination-Path/ --ssh --host 192.168.1.104 --user USERNAMEHERE --password 'PASSWORDHERE' --no-compare-types --export-html report.html

# Guided workflow (menu)
python3 hashbackup_R2.py

# Default options mode
python3 hashbackup_R3.py

# Advanced interactive mode with Norton-Commander–style browsing
python3 hashbackup_R4.py

# Command-line mode
python3 hashbackup_R4.py 
