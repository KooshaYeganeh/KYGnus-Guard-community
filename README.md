# KYGnus Guard community
KYGnus Antivirus For Linux Systems

# INFO

This App is Linux Security Tool But it's nut Just Pure Antivirus.This app Have:
1- Pure Antivirus for Detect Files Have potantional Malicious
2- Search page for Search in Malicious Urls
3- check Permissions of system 
4- check configs
5- Scan Remote system with clamAV





# Install

## For Install App Follow the steps below:

1- create App Directory in hone of user for Example:  
*Note : replace my username(koosha) with Your ursername in command below*

**$ mkdir /home/koosha/App && cd /home/koosha/App**

2- Goes To App Directory and Get File From Github

**$ wget https://github.com/KooshaYeganeh/KYGnus-Guard-community/archive/refs/heads/main.zip**

3- Unzip File  
**$ unzip main.zip**

4- Go to Directory  
**$ cd KYGnus-Guard-community-main/**

5- create virtualenv 
**$ virtualenv venv**

*Note : if virtualenv Not Installed on You system install it with this command:*  
> sudo pip install virtualenv

6- Create database in mariaDB  
*Note : if Mariadb Not installed on system Install it*
[For more Information About Install mariaDB on Fedora35](https://docs.fedoraproject.org/en-US/quick-docs/installing-mysql-mariadb/)
[For more Information About Install mariaDB on Ubuntu 20.04 ](https://www.digitalocean.com/community/tutorials/how-to-install-mariadb-on-ubuntu-20-04)


7- Edit KYGnus_Guard.sh File:  
 - 7-1 : in KYGnus_guard.sh File You Should First chanage Username with Your user  
*Note: if You use Debian Base systems Like Ubuntu You chould change command python with python3.*  
*Note: in RedHat Base systems Like Fedora You Don't Need chnage python command because in Default mode python Running python3 command.*

6- change Service File :  
 - 6-1: change user(koosha) with Your user in Line : /home/**koosha**/App/KYGnus_Guard_community/KYGnus_Guard.sh

7- copy service File in /etc/systemd/system Directory

**$ sudo cp KYGnus_Guard.service  /etc/systemd/system directory**


8 - Enable Service File

**$ cd /etc/systemd/system/**  
**$ sudo systemctl enable --now KYGnus_Guard.service**

9 - for Better Security You should Block 8080 port in Your system

**$ sudo iptables -t filter -A INPUT -p tcp -i any --dport 8080 -j DROP**














## TODO :

 - [X] Scan system For Maliciuos Files
 - [X] Scan Remote System with ClamAV
 - [X] Search In  Malicious URL's 
 - [X] Check Permissions
 - [X] check MariaDB configs 
