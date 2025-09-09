#!/bin/bash

# ANSI colors
RED='\033[1;31m'
GREEN='\033[1;32m'
RESET='\033[0m'

linux_distro=$(awk -F= '$1=="PRETTY_NAME" {print $2}' /etc/os-release | tr -d '"' | cut -d ' ' -f1) 
echo "Linux Distro: $linux_distro"

case $linux_distro in
	"Ubuntu")
		sudo apt update
		sudo apt upgrade
		sudo apt install cmake
		sudo apt install openssl libssl-dev

		exit_status=$?
		
		if [ "$exit_status" -eq 0 ]; then
			echo -e "\n${GREEN}[+] Setup Success!${RESET}"
		else
			echo -e "\n${RED}[-] Failed to install dependencies${RESET}"
		fi
		;;

	*)
		;;
esac
