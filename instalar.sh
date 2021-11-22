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
#apt install bloodhound neo4j
docker pull neo4j
docker run -p 7474:7474 -p 7687:7687 neo4j
docker pull byt3bl33d3r/crackmapexec
cp ADtester.sh /usr/bin/
