#!/bin/bash
cd ..
python -m venv DRAXTER
cd DRAXTER
./bin/pip install --upgrade pip
./bin/python ./bin/pip install -r requirements.txt
sudo dpkg -i tools/libssl1.1_1.1.1w-0+deb11u4_amd64.deb
sudo dpkg -i tools/wkhtmltox_0.12.6.1-2.bullseye_amd64.deb
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj "/C=GE/L=Tbilisi/O=DRACSEC/OU=DRAGOWN/CN=localhost"
./bin/python indb.py
