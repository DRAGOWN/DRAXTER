<img src="https://raw.githubusercontent.com/DRAGOWN/DRAXTER/refs/heads/main/draxter/static/logo.png" align="center" width="900">

## DRAXTER

<b> Draxter tool is used for managing a big list of IP addresses and ports for your pentest project.</b> It’s designed to take an XML scan input, filter targets by criteria (ports or services), and export or run selected actions against those targets to support your pentest workflow.

### Instalation & Execution
❗❗❗ Compatible with Kali Linux using kali default user

1. `git clone https://github.com/DRAGOWN/DRAXTER.git`
2. `cd DRAXTER`
3. `chmod 750 install.sh run.sh`
4. `./install.sh`
5. Set credentials
6. `./run.sh`

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

Demo of HTTP scanning and autoscreenshot:

<img width="849" alt="image" src="https://github.com/user-attachments/assets/7d228f35-326a-466c-a9ff-0df21f8d84b7" />

> Filtering the ports with regex input

<img width="849" alt="image" src="https://github.com/user-attachments/assets/519b1f3a-f502-4a9a-814f-7d862a1f059f" />

> Exporting HTTP(s) Format

<img width="849" alt="image" src="https://github.com/user-attachments/assets/3be6014a-2304-4b55-9e34-883e2593f2fd" />

> Selecting the execution command

<img width="849" alt="image" src="https://github.com/user-attachments/assets/7520d9d0-dd58-46af-8af6-db8787c16049" />

> Checking the screenshots in the Browse

<img width="849" alt="image" src="https://github.com/user-attachments/assets/f53e6562-1edc-4ebf-8e46-40bcb85cd995" />

> Checking screenshots directly in browser


<img src="https://raw.githubusercontent.com/DRAGOWN/DRAXTER/refs/heads/main/draxter/static/Welcome.png" align="right" width="200">
