**Secure File Transfer**

**Introduction**
With the increasing need for secure file sharing, this project provides a **Secure File Transfer** system that ensures confidentiality using encryption techniques. The system allows users to encrypt files before transferring them and decrypt them after retrieval, ensuring data security.

 **Features**
- **User Authentication**: Secure registration and login system.
- **File Encryption & Decryption**: Uses **Fernet encryption** to protect files.
- **Activity Tracking**: Logs encryption and decryption actions.
- **Profile Management**: Users can update their details.
- **User-Friendly UI**: Responsive and modern design for easy use.

**Technology Stack**
- **Backend**: Flask (Python)
- **Frontend**: HTML, CSS
- **Database**: SQLite
- **Encryption**: Cryptography (Fernet)

**Installation & Setup**
**1. Clone the repository:**
```sh
git clone https://github.com/your-username/secure-file-transfer.git
cd secure-file-transfer
```
 **2. Install dependencies:**
```sh
pip install -r requirements.txt
```
**3. Generate encryption key:**
```sh
python -c "from encryption import generate_key; generate_key()"
```
**4. Run the application:**
```sh
python app.py
```
**5. Access the system**
Open a browser and go to: `http://127.0.0.1:5000/`

**Usage**
- **Encrypt a file**: Upload a file, encrypt it, and download the encrypted version.
- **Decrypt a file**: Upload an encrypted file and get back the original.
- **Track activities**: View the history of encryption and decryption actions.

**Future Enhancements**
- Implement **two-factor authentication (2FA)**.
- Support additional file formats.
- Enhance UI with **JavaScript and Bootstrap**.
- Deploy on **cloud platforms**.

**Contributors**
- **Abhinav**

**License**
This project is open-source and available under the MIT License.

---
**GitHub Repository:** https://github.com/abhinav160/Secure-File-Transfer.git

