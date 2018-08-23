#!/bin/bash

# Make sure the current directory is eventsentry.
CURRENT_DIR=${PWD##*/}
if [ "$CURRENT_DIR" != "eventsentry" ]; then
    echo "You must run this script from within the eventsentry directory!"
    exit
fi

echo "
███████╗██╗   ██╗███████╗███╗   ██╗████████╗    ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗
██╔════╝██║   ██║██╔════╝████╗  ██║╚══██╔══╝    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝
█████╗  ██║   ██║█████╗  ██╔██╗ ██║   ██║       ███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝
██╔══╝  ╚██╗ ██╔╝██╔══╝  ██║╚██╗██║   ██║       ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝
███████╗ ╚████╔╝ ███████╗██║ ╚████║   ██║       ███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║
╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═══╝   ╚═╝       ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝

Welcome to the Event Sentry installer.
"

# Prompt for install directory.
echo "Desired installation directory:"
read INSTALL_DIR
if [[ $INSTALL_DIR = *"~"* ]]; then
    INSTALL_DIR="${INSTALL_DIR/#\~/$HOME}"
fi
echo ""
echo "Confirm install directory: $INSTALL_DIR"
select yn in "Yes" "No"; do
    case $yn in
        Yes ) break;;
        No ) echo "Exiting."; exit;;
    esac
done
echo ""

# Make sure the installation direct does not already exist.
if [ -d "$INSTALL_DIR" ]; then
    echo "[!] Installation directory already exists! Exiting."
    exit
fi

# Create the installation directory.
echo "[*] Creating the installation directory."
mkdir -p $INSTALL_DIR

# Copy the files to the installation directory.
cp -r ./* $INSTALL_DIR

# cd into the installation directory.
cd $INSTALL_DIR

# Create and activate a new virtual environment.
echo "[*] Creating new Python virtual environment."
python3 -m venv venv
. $INSTALL_DIR/venv/bin/activate

# Install requirements.txt
echo "[*] Installing Python dependencies."
pip3 install -r requirements.txt 

# Install some apt-get dependencies.
echo "[*] Installing apt-get dependencies."
sudo apt install -y build-essential gcc make libyaml-dev geoip-database geoip-bin

# Update the GeoIP database files.
echo "[*] Downloading new GeoIP database files."
geo_path=/usr/share/GeoIP/
wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz
wget http://geolite.maxmind.com/download/geoip/database/GeoIPv6.dat.gz
wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
wget http://geolite.maxmind.com/download/geoip/database/GeoLiteCityv6-beta/GeoLiteCityv6.dat.gz
wget http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz
wget http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNumv6.dat.gz
gunzip *.gz
sudo mv *.dat $geo_path

# Install proxychains-ng
echo "[*] Downloading proxychains-ng."
cd $INSTALL_DIR/bin
git clone https://github.com/rofl0r/proxychains-ng.git
echo "[*] Building proxychains-ng from source."
cd $INSTALL_DIR/bin/proxychains-ng
./configure --prefix=/usr --sysconfdir=/etc
make

# Install getitintocrits.py
echo "[*] Downloading getitintocrits."
cd $INSTALL_DIR/bin
git clone https://github.com/IntegralDefense/getitintocrits.git

# Install splunklib
echo "[*] Downloading splunklib."
cd $INSTALL_DIR/bin
git clone https://github.com/IntegralDefense/splunklib.git

# Copy config files into their local directories
cd $INSTALL_DIR
cp etc/config.ini etc/local/
cp etc/proxychains.conf etc/local/
cp lib/modules/detections/etc/*.ini lib/modules/detections/etc/local/
cp bin/getitintocrits/etc/*.ini bin/getitintocrits/etc/local/
cp etc/splunklib.ini $HOME/.splunklib.ini
echo ""
echo ""

echo "[*] Installation complete!"

echo ""
echo ""

echo "[!] Before you can run Event Sentry, you must edit some config files:"
echo "        Main Event Sentry config: $INSTALL_DIR/etc/local/config.ini"
echo "        Detection modules config: $INSTALL_DIR/lib/modules/detections/etc/local/*.ini"
echo "        proxychains config:       $INSTALL_DIR/etc/local/proxychains.conf"
echo "        getitintocrits config:    $INSTALL_DIR/bin/getitintocrits/etc/local/config.ini"
echo "        splunklib config:         $HOME/.splunklib.ini"
echo "        cbinterface config:       /etc/carbonblack/credentials.response"

echo ""
echo ""

echo "[!] When you have edited the config files, you can start/stop Event Sentry with:"
echo "        $INSTALL_DIR/bin/start"
echo "        $INSTALL_DIR/bin/stop"
echo ""
