#!/bin/bash

apt install libsnmp-dev snmp-mibs-downloader gcc python3-dev python-dev &&
pip3 install -r requirements.txt &&

rm -rf /usr/bin/async-connect-scan 2>/dev/null
rm -rf /usr/bin/async-snmp-scan 2>/dev/null
rm -rf /usr/bin/async-web-scan 2>/dev/null
rm -rf /usr/bin/async-web-fuzzer 2>/dev/null

link async-connect-scan.py /usr/bin/async-connect-scan &&
link async-snmp-scan.py /usr/bin/async-snmp-scan &&
link async-web-scan.py /usr/bin/async-web-scan &&
link async-web-fuzzer.py /usr/bin/async-web-fuzzer &&
echo 'OK.'
