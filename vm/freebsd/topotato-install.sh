#!/usr/local/bin/bash

cd /home/vagrant/dev/topotato
pkg update -f
pkg install -y graphviz \
            python39 \
            py39-pip \
            py39-pytest \
            py39-lxml \
            wireshark

rm /usr/local/bin/python || true
ln -s /usr/local/bin/python3.9 /usr/local/bin/python
pip install -r requirements.txt
echo "export PATH=/home/vagrant/.local/bin:\$PATH" >> /home/vagrant/.bashrc