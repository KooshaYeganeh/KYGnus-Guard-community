# KYGnus-AV
minimal Antivirus with Bashscript


# INFO

This Script helps for system Admins and who works with Linux to Find Malicious Files

Note : if You install sshfs you can mount other system Devices to You system and Scan That

> For install sshfs

Redhat base systems: 
$ sudo dnf install sshfs

Debian base systems:

$ sudo apt update && sudo apt install sshfs


# Install

1 - be root
$ sudo su - 

2 - run This command
$ cd /opt && wget https://github.com/KooshaYeganeh/KYGnus-AV/archive/refs/heads/main.zip && unzip main.zip && cd KYGnus-AV-main && cp KYGnus-AV /usr/bin && cd 



# Run

KYGnus-AV


# remove

sudo rm -rf /opt/KYGnus-AV-main && sudo rm main.zip && sudo rm /usr/bin/KYGnus-AV
