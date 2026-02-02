<img src="https://raw.githubusercontent.com/DRAGOWN/DRAXTER/refs/heads/main/draxter/static/logo.png" align="center" width="900">

## DRAXTER

<b> Draxter tool is used for managing a big list of IP addresses and ports for your pentest project.</b> It’s designed to take an XML scan input, filter targets by criteria (ports or services), and export or run selected actions against those targets to support your pentest workflow.

### Instalation & Execution
❗❗❗ Compatible with Kali Linux using kali default user
```
git clone https://github.com/DRAGOWN/DRAXTER.git
cd DRAXTER
chmod 750 install.sh run.sh
./install.sh
./run.sh
```
### Requirements

* Flask==3.0.3
* Flask-SQLAlchemy==3.1.1
* Flask-Login==0.6.3
* pandas>=2.2.2
* openpyxl==3.1.2
* SQLAlchemy>=2.0.36

### Steps

1. Upload XML format of nmap scan
2. Filter by specific port(s) or (services)
3. Export a file of the targets
4. Select the specific attack
5. Execute the selected command according your testing purposes

Common Attacks:
1. Auto screenshot a big list of HTTP(s) targets (thanks to gobuster)
2. Auto screenshot a big list of RDP targets with NLA disabled (thanks to netexec)
3. Auto scan a big list of targets with the following service protocols:

    3.1. SSHWMI, SMB, HTTP, HTTPS, LDAP, RDP, VNC, MSSQL, NFS, WINRM, FTP

Demo

<img width="900" height="317" alt="image" src="https://github.com/user-attachments/assets/0dcdc87a-ac75-4555-8347-3f58d9eea5a2" />

> Step #1: Name project and upload nmap scan in XML format

<img width="900" height="317" alt="image" src="https://github.com/user-attachments/assets/bb4456ae-e3bb-4733-be3e-826ee084e74f" />

> XML file uploaded: You can search service/port by integrated dukduckgo search

<img width="900" height="943" alt="image" src="https://github.com/user-attachments/assets/9916248b-1735-44fe-9748-2d9fe21fb08f" />

> Redirected to duckduckgo with specific dork

<img width="900" height="552" alt="image" src="https://github.com/user-attachments/assets/57a00191-8b0f-4b04-9e84-8015878c0fbf" />

> Exporting all IP addresses with 3389 port open in TXT file

<img width="900" height="365" alt="image" src="https://github.com/user-attachments/assets/4e98a1fe-7a20-4b0b-b90a-1f43cc6fe971" />

> The file is saved locally

<img width="900" height="588" alt="image" src="https://github.com/user-attachments/assets/d46db95f-6a4b-4425-92cf-68f6bb3bbbe3" />

> After genereting targets file, you can start attack against them 

<img width="900" height="381" alt="image" src="https://github.com/user-attachments/assets/5010af2f-32f4-4163-9c42-1be1494b7bf3" />

> Select specific attack according to the service/port. Pre-prepared command is ready for you selecting the generetad IP addresses as values, additionally you can execute authenticated scan

<img width="900" height="74" alt="image" src="https://github.com/user-attachments/assets/a907906c-c369-40c3-8304-c1808b3d264e" />

> Copy-pasting command and executing in the terminal

<img width="900" height="376" alt="image" src="https://github.com/user-attachments/assets/7ed79ec1-23ec-441d-a933-9496f433ec10" />

> After the scan is completed, click the File System icon

<img width="900" height="469" alt="image" src="https://github.com/user-attachments/assets/0b6caf1e-d1d8-4b85-924b-163261188695" />

> The folders are created and PoCs are visible in the web.

All these steps may seem childish, but it is convenient when managing and attacking against a huge list of IP addresses with even more ports open.


<img src="https://raw.githubusercontent.com/DRAGOWN/DRAXTER/refs/heads/main/draxter/static/Welcome.png" align="right" width="200">
