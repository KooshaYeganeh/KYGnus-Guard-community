# KYGnus Guard community
KYGnus Antivirus For Linux Systems

![image](./static/README_LOGO.png)

## INFO

This App is Linux Security Tool But it's nut Just Pure Antivirus.This app Have:  
1- Pure Antivirus for Detect Files Have potantional Malicious  Files 
2- Search page for Search in Malicious Urls  
3- Visit Permissions of System and Save them
4- check configs  
5- Scan Local system with clamav
6- Scan Remote system with clamAV





## Install

## For Install App Follow the steps below:

**1-Change Directory to /tmp and Download File From GitHub**

```
cd /tmp && wget https://github.com/KooshaYeganeh/KYGnus-Guard-community/archive/refs/heads/main.zip && unzip main.zip && mv KYGnus-Guard-community-main KYGnus-Guard-Community && cd
```

```
sudo mv /tmp/KYGnus-Guard-Community /home/$USER/ && cd /home/$USER && mv KYGnus-Guard-Community .KYGnus-Guard-Community
```
**2-Create venv in App Directory**

First First, we check that the pipe is installed correctly on the system, then Install virtualenv with pip

```
sudo pip install virtualenv
```
then Create virtuelenv in main Directory and Activate 
```
cd /home/$USER/.KYGnus-Guard-Community && virtualenv venv && source venv/bin/activate
```

**3- Install python Packages**  
```
Fedora: pip install -r requirements.txt
Ubuntu: pip3 install -r requirements.txt
openSUSE Leap : pip install -r requirements.txt
```

Note : if get Error when Install Packeges Like Version Error You can remove Version of Packages in requirements File Like this: 

> sed 's/==.*//g' requirements.txt > requirements.txt

or run This Script

```
./pkg
```

Note2 : When Remove Version of Packages Latest Version of Packes Will be Install

**4- Create database in mariaDB**  
*Note : if Mariadb Not installed on system Install it*  
[For more Information About Install mariaDB on Fedora35](https://docs.fedoraproject.org/en-US/quick-docs/installing-mysql-mariadb/)  
[For more Information About Install mariaDB on Ubuntu 20.04 ](https://www.digitalocean.com/community/tutorials/how-to-install-mariadb-on-ubuntu-20-04)  
[For more Information About Install mariaDB on OpenSuse: OpenSuse4Developers](https://github.com/KooshaYeganeh/OpenSuse4Developers)

Note : Installation of MariaDB in openSuse Same as ubuntu

**5- create database malware_comminitu in MariaDB**

```
CREATE DATABASE malware_community;
```

**6- Restore malware.sql database to Your DB and insert shellTable**

```
mysql -u <user> -p  malware_community < malware_comminity.sql
```


**7- Change config (config.py) File From Your Configurations**


**8- copy Main File to /usr/bin and Run App For First Time**

```
sudo mv /home/$USER/.KYGnus-Guard-Community /usr/bin
```
```
kyguard --start
```
*For More Information About kyguard command :*
```
kyguard --help
```


Note : in opensuse you Might see seLinux status Error,You should Install selinux Packages : 

```
sudo zypper in restorecond policycoreutils setools-console
```
  
*Note: in RedHat Base systems Like Fedora You Don't Need chnage python command because in Default mode python Running python3 command.*







**9- Create Directory For standard Logs /var/log**
*Note: change user(koosha) with Your user in all lines*
 - 15-1 : Go to /var/log Directory and make Directory for app
```
cd /var/log
```
```
sudo mkdir KYGnus-Guard-Community
```

```
sudo ln -s /home/$USER/.KYGnus-Guard-Community/Log KYGnus-Guard-Community
```

**10- Create Directory For standard Settings /etc**
*Note: change user(koosha) with Your user in all lines*
 - 16-1 : Go to /etc Directory and make Directory for app
```
cd /etc
```
```
sudo mkdir KYGnus-Guard-Community
```
```
cd KYGnus-Guard-Community
```
```
sudo ln -s  /home/$USER/.KYGnus-Guard-Community/config.py KYGnus-Guard-Community.conf
```


**11- for Better Security You should Block 8080 port in Your system**

```
sudo iptables -t filter -A INPUT -p tcp -i any --dport 8080 -j DROP
```

## Remove

```
sudo iptables -F && sudo rm /etc/systemd/system/KYGnus-Guard-Community.service && sudo rm -rf /var/log/KYGnus-Guard-Community && sudo rm -rf /etc/KYGnus-Guard-Community  && rm -rf /home/$USER/.KYGnus-Guard-Community && mysql --execute="DROP DATABASE malware_community;"
```



