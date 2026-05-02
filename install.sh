#!/bin/bash
set -e

echo "Building DNS Ad Blocker..."
mkdir -p build
cd build
cmake ..
make -j$(nproc)
cd ..

echo "Installing to /usr/local/bin..."
sudo cp build/dns-ad-blocker /usr/local/bin/

echo "Creating configuration directory in /etc/dns-ad-blocker..."
sudo mkdir -p /etc/dns-ad-blocker
sudo cp config/settings.conf config/blocklist.txt config/whitelist.txt /etc/dns-ad-blocker/

echo "Installing systemd service..."
sudo cp dns-ad-blocker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable dns-ad-blocker
sudo systemctl restart dns-ad-blocker

echo "Installation complete! The DNS Ad Blocker is now running as a service."
echo "You can check its status with: sudo systemctl status dns-ad-blocker"
echo "To reload blocklists, run: sudo systemctl reload dns-ad-blocker"
