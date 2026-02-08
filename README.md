<img src="https://raw.githubusercontent.com/DRAGOWN/DRAXTER/refs/heads/main/draxter/static/logo.png" align="center" width="900">

## DRAXTER - PROOF IN 1 CLICK

<b> Draxter tool is used for managing a big list of IP addresses and ports for your pentest project.</b> It’s designed to take an XML scan input, filter targets by criteria (ports or services), and export or run selected actions against those targets to support your pentest workflow.

### Instalation & Execution
❗❗❗ Compatible with Kali Linux using kali default user

1. `git clone https://github.com/DRAGOWN/DRAXTER.git`
2. `cd DRAXTER`
3. `chmod 750 install.sh run.sh`
4. `./install.sh`
5. You will be asked to input sudoer's password
6. Set application credentials
7. `./run.sh`
8. Browse: https://localhost:5000 

### Requirements
  Pip
* Flask==3.0.3
* Flask-SQLAlchemy==3.1.1
* Flask-Login==0.6.3
* imgkit==1.2.3
* ansi2html==1.9.2
* pandas>=2.2.2
* openpyxl==3.1.2
* SQLAlchemy>=2.0.36
  Deb
* libssl1.1
* wkhtmltox_0.12.6.1


### Steps

1. Upload XML format of nmap scan
2. Filter by specific port(s) or (services)
3. Export a file of the targets
4. Select the specific attack
5. Execute the selected command according your testing purposes

### Common Attacks:

1. Auto screenshot a big list of HTTP(s) targets (thanks to gowitness)
2. Auto screenshot a big list of RDP targets (thanks to netexec)
3. Auto scan a big list of targets with the following service protocols:

   3.1. SSH, WMI, SMB, HTTP, HTTPS, WebDAV, LDAP, RDP, VNC, MSSQL, NFS, WINRM, FTP, SSL, Redis, NFS, etc.

### Export Targets:

* Unique IP Export
* HTTP(S) Targets Export
* Customized Columns Export in XLSX 

### Improvements in v1.5
* Redesigned CMD Execution Windows
* Terminal screenshot per connection
* Added protocol enumeration tags
* Moore targeted templates

This is just a beginning 💥

<img src="https://raw.githubusercontent.com/DRAGOWN/DRAXTER/refs/heads/main/draxter/static/Welcome.png" align="right" width="200">
