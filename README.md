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
sudo mv /tmp/KYGnus-Guard-Community /opt && cd /opt/KYGnus-Guard-Community
```

**2-Test the pip Package Manager and then Install the packages**

First First, we check that the pip is installed correctly on the system, then Install packages

*pip -V*

Fedora: 

```
sudo pip install -r requirements.txt
```

Ubuntu: 

```
sudo pip3 install -r requirements.txt
```
openSUSE Leap : 

```
sudo pip install -r requirements.txt
```

Note : if get Error when Install Packeges Like Version Error You can remove Version of Packages in requirements File Like this: 

> sed 's/==.*//g' requirements.txt > requirements.txt

or run This Script

```
./pkg
```

Note2 : When Remove Version of Packages Latest Version of Packes Will be Install

**3- Create database in mariaDB**  
*Note : if Mariadb Not installed on system Install it*  
[For more Information About Install mariaDB on Fedora35](https://docs.fedoraproject.org/en-US/quick-docs/installing-mysql-mariadb/)  
[For more Information About Install mariaDB on Ubuntu 20.04 ](https://www.digitalocean.com/community/tutorials/how-to-install-mariadb-on-ubuntu-20-04)  
[For more Information About Install mariaDB on OpenSuse: OpenSuse4Developers](https://github.com/KooshaYeganeh/OpenSuse4Developers)

Note : Installation of MariaDB in openSuse Same as ubuntu

**4- Create Database malware_comminitu in MariaDB**

**ٔNote :** *If the database is located in the local system, it is better to put the username and password of the database in the /etc/my.conf file so that it is easy to log in and work with the database.*


[client]
user = mysqluser
password = mysqlpassword

> change dbuser with your databaseuser and dbpassword with your database password in command below 

```
echo -e "[clinet-server]\n\n[client]\nuser=dbuser\npassword=dbpassword\n\n!includedir /etc/my.cnf.d" > /tmp/my.cnf
```


```
create database malware_community;
```

**5- Restore malware_community.sql database to Your DB and insert shellTable**

```
mysql -u root -p  malware_community < malware_community.sql
```


**6- Change config (config.py) File From Your Configurations**


**7- Run App For First Time**

Note : in openSUSE you Might see SELinux status Error,You should Install SELinux Packages : 

```
sudo zypper in restorecond policycoreutils setools-console
```
  
*Note: in RedHat Base systems Like Fedora You Don't Need chnage python command because in Default mode python Running python3 command.*




**8- copy service File in /etc/systemd/system Directory**

```
sudo cp KYGnus_Guard.service  /etc/systemd/system 
```

**9- Enable Service File**

```
cd /etc/systemd/system/ && sudo systemctl enable KYGnus_Guard.service && sudo systemctl start  KYGnus_Guard.service && cd && echo "Service File [ OK ]"
```




**10- Create Directory For standard Logs /var/log**
*Note: change user(koosha) with Your user in all lines*
 - 15-1 : Go to /var/log Directory and make Directory for app

```
cd /var/log && sudo mkdir KYGnus-Guard-Community && sudo ln -s /opt/KYGnus-Guard-Community/Log KYGnus-Guard-Community && cd && echo "Standard Log File Created Successfully [ OK ]"
```

**11- Create Directory For standard Settings /etc**
*Note: change user(koosha) with Your user in all lines*
 - 16-1 : Go to /etc Directory and make Directory for app

```
cd /etc && sudo mkdir KYGnus_Guard && cd KYGnus_Guard && sudo ln -s  /opt/KYGnus-Guard-Community/config.py KYGnus-Guard.conf && cd && echo "Standard config File Created Successfully [ OK ]"
```


**12- for Better Security You should Block 8080 port in Your system**

```
sudo iptables -t filter -A INPUT -p tcp -i any --dport 8080 -j DROP
```



### Groupe Installer

Ansible software can be used to install the software on several hosts at the same time. To do this, just run the grp_install script.  

**Note 1:** Note that the database is on your system, and if the database is placed on the remote system, delete the relevant line from the script.  

**Note 2 :** In the script, all the hosts are taken into account. In order to specify specific hosts for installation, change the host on the playbook.


```
ansible-playbook grp_install.yml
```


## Remove

```
sudo iptables -F && sudo rm /etc/systemd/system/KYGnus_Guard.service && sudo rm -rf /var/log/KYGnus-Guard-Community && sudo rm -rf /etc/KYGnus-Guard-Community  && rm -rf /opt/KYGnus-Guard-Community && mysql --execute="DROP DATABASE malware_community;" && echo "KYGnus-Guard-Community Removed [ Successfully ]"
```



### Groupe Remove

```
ansible-playbook grp_remove.yml
```