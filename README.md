# KYGnus Guard community
KYGnus Antivirus For Linux Systems

![image](./static/README_LOGO.png)

# INFO

This App is Linux Security Tool But it's nut Just Pure Antivirus.This app Have:  
1- Pure Antivirus for Detect Files Have potantional Malicious  Files 
2- Search page for Search in Malicious Urls  
3- check Permissions of system  
4- check configs  
5- Scan Remote system with clamAV





# Install

## For Install App Follow the steps below:

**1-chnage Directory to /opt**

``
 cd /opt
``

**2-Download File From Github**

```
wget https://github.com/KooshaYeganeh/KYGnus-Guard-community/archive/refs/heads/main.zip

```
**3- Unzip File**  
```
unzip main.zip && mv KYGnus-Guard-community-main KYGnus_Guard
```
**Create Directory for App in /opt**
```
sudo mv KYGnus_Guard /opt
```

**4- Go to Directory**  
```
cd /opt/KYGnus_Guard
```

**5- Install python Packages**  
```
Fedora: sudo pip install -r requirements.txt
Ubuntu: sido pip3 install -r requirements.txt
openSUSE Leap : sudo pip install -r requirements.txt
```

Note : if get Error when Install Packeges Like Version Error You can remove Version of Packages in requirements File Like this: 

> vi requirements.txt
> :%s/==.*//g

or run This Script

```
./pkg
```

Note2 : When Remove Version of Packages Latest Version of Packes Will be Install

**6- Create database in mariaDB**  
*Note : if Mariadb Not installed on system Install it*  
[For more Information About Install mariaDB on Fedora35](https://docs.fedoraproject.org/en-US/quick-docs/installing-mysql-mariadb/)  
[For more Information About Install mariaDB on Ubuntu 20.04 ](https://www.digitalocean.com/community/tutorials/how-to-install-mariadb-on-ubuntu-20-04)  
[For more Information About Install mariaDB on OpenSuse: OpenSuse4Developers](https://github.com/KooshaYeganeh/OpenSuse4Developers)

Note : Installation of MariaDB in openSuse Same as ubuntu

**7- create database malware in mariaDB**

```
create database malware;
```

**8- Restore malware.sql database to Your DB and insert shellTable**

```
mysql -u root -p  malware < malware.sql
```

```
./insert_mysql
```

**9- Change config (config.py) File From Your Configurations**


**10- Run App For First Time**

Note : in opensuse you Might see seLinux status Error,You should Install selinux Packages : 

```
sudo zypper in restorecond policycoreutils setools-console
```
  

**11- Edit KYGnus_Guard.sh File:**  
 - 11-1 : in KYGnus_guard.sh File You Should First chanage Username with Your user  
*Note: if You use Debian Base systems Like Ubuntu and openSuse You chould change command python with python3.*  
*Note: in RedHat Base systems Like Fedora You Don't Need chnage python command because in Default mode python Running python3 command.*

**12- change Service File :**  
 - 12-1: change user(koosha) with Your user in Line : /opt/KYGnus-Guard-community-main/KYGnus_Guard.sh

**13- copy service File in /etc/systemd/system Directory**

```
sudo cp KYGnus_Guard.service  /etc/systemd/system directory
```

**14 - Enable Service File**

```
cd /etc/systemd/system/
```
```
sudo systemctl enable --now KYGnus_Guard.service
```
Note : In some Linux distributions, an error may occur in the start service, which may be due to the bash call path. In this case, modify the KYGnus_Guard.sh file and put your system bash call path in the file.
for Example:
Fedora : /usr/bin/bash
OpenSuse : /usr/bin/bash
Peppermint : /bin/bash



**15- Create Directory For standard Logs /var/log**
*Note: change user(koosha) with Your user in all lines*
 - 15-1 : Go to /var/log Directory and make Directory for app
```
cd /var/log
```
```
sudo mkdir KYGnus_Guard
```
```
cd KYGnus_Guard
```
```
ln -s /opt/KYGnus-Guard-community-main/Log/KYGnus_Guard.log KYGnus_Guard.log
```

**16- Create Directory For standard Settings /etc**
*Note: change user(koosha) with Your user in all lines*
 - 16-1 : Go to /etc Directory and make Directory for app
```
cd /etc
```
```
sudo mkdir KYGnus_Guard
```
```
cd KYGnus_Guard
```
```
ln -s /opt/KYGnus-Guard-community-main/config.py KYGnus_Guard.conf
```


**17- for Better Security You should Block 8080 port in Your system**

```
sudo iptables -t filter -A INPUT -p tcp -i any --dport 8080 -j DROP
```













## TODO :

 - [X] Scan system For Maliciuos Files
 - [X] Scan Remote System with ClamAV
 - [X] Search In  Malicious URL's 
 - [X] Check Permissions
 - [X] check MariaDB configs 
