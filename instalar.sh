function print_ascii_art {
cat << "EOF"
AD TESTER
			daniel.torres@owasp.org
			https://github.com/DanielTorres1

EOF
}


print_ascii_art

RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal


echo -e "${RED}[+]${BLUE} Instalar craclmapexec ${RESET}"
apt install bloodhound neo4j rdate

docker pull byt3bl33d3r/crackmapexec
cp ADtester.sh /usr/bin/

rm /usr/bin/cme 2>/dev/null
echo "alias cme='docker run  -it byt3bl33d3r/crackmapexec'" >> ~/.bashrc

echo -e "${RED}[+]${BLUE} Instalar bloodhound ${RESET}"
apt-get install bloodhound
pip install bloodhound 


echo -e "${GREEN} [+] Modificando PATH ${RESET}"
cp -r ADTestBin /usr/bin/ADTestBin/
chmod a+x /usr/bin/ADTestBin/*
echo export PATH="$PATH:/usr/bin/ADTestBin" >> ~/.bashrc
echo export PATH="$PATH:/usr/bin/ADTestBin" >> ~/.zshrc
echo ""
