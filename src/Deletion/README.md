# Digital Forensics – Secure Deletion & Mitigation Tool

## Project Overview
This tool is designed for demonstrating secure data deletion and forensic mitigation techniques. It allows users to perform standard and secure file deletions, and then verify the effectiveness of those deletions by scanning for recoverable traces on the system.

## Key Features
- **File Management**: Browse the local filesystem and inspect file metadata.
- **Unified Deletion**: Choose between Normal (Recycle Bin), Permanent (Direct removal), and Secure (Overwrite then remove) deletion methods.
- **Secure Overwrite Engine**: Implements binary-level overwriting with Zeros, Random, or Dummy patterns to prevent forensic recovery.
- **Recovery Check (Verification)**: Scans for lingering artifacts, bit-stream signatures, and metadata remnants to prove recovery is impossible after secure deletion.
- **Mitigation & Viva Help**: Integrated educational section with technical explanations for common digital forensics questions.
- **Forensic Logging**: maintains a structured record of all forensic operations with timestamps and detailed status.

## Directory Structure
- `main_gui.py`: The central Tkinter GUI application.
- `secure_deletion.py`: Core engine for binary-level data overwriting.
- `deletion_techniques.py`: Logic for different deletion strategies.
- `post_deletion_verification.py`: Verification logic to check for recoverable data.
- `forensic_logger.py`: Structured logging system.
- `environment_setup.py`: Automates the creation of the forensic analysis directory structure.

## Installation
1. Ensure you have Python 3.x installed.
2. Install the necessary dependencies (optional):
   ```bash
   pip install -r requirements.txt
   ```
   *Note: `send2trash` is optional but recommended for Recycle Bin integration.*

## Usage
Run the main GUI application:
```bash
python main_gui.py
```

## Credits
Implemented by **Member 2: Secure Deletion & UI Lead** for the Ethical Hacking Mini Project.
