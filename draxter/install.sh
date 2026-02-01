#!/bin/bash
cd ..
python -m venv draxter
cd draxter
./bin/pip install --upgrade pip
./bin/python ./bin/pip install -r requirements.txt
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj "/C=GE/L=Tbilisi/O=DRAGOWN/OU=DRAGOWN/CN=localhost"
./bin/python indb.py
