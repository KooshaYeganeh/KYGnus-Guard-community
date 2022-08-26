from urllib import response
from flask import Flask, Response, redirect, render_template_string, session, abort,render_template
from flask import request, url_for,flash
from flask import send_file
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
import datetime
import getpass
import glob
import logging
import os
import pipes
import pymysql
import re
import schedule
import shutil
import sys
import time
from cryptography.fernet import Fernet
import pyfiglet
import sys
import socket
from datetime import datetime
from colorama import init, Fore, Back, Style
import config
from socket import *



username = getpass.getuser()


appdir = os.path.join(f"/home/{username}/KYGnus_Guard_community")
os.makedirs(appdir,exist_ok=True)

Quarantine = os.path.join(f"/home/{username}/KYGnus_Guard_community/Quarantine")
os.makedirs(Quarantine,exist_ok=True)



app = Flask(__name__)



logging.basicConfig(filename=f"{appdir}/KYGnus_Guard.log",
                    format='%(asctime)s %(message)s',
                    filemode='w')

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)







def connect_db():
    db = pymysql.connect(host=config.DB_HOST,
                     user=config.DB_USER,
                     passwd=config.DB_PASSWORD,
                     db=config.DB,
                     port=config.DB_PORT,
                     charset='utf8',
                     use_unicode=True)
    return db



def se_status():
    selinux = "sestatus | grep 'Current mode' | awk {'print $3'}"
    status = os.popen(selinux).read()
    return status

def firewall_status():
    firewalld = "systemctl | grep firewalld | awk {'print $4'}"
    status = os.popen(firewalld).read()
    return status

def maria_status():
    mariadb = "systemctl | grep mariadb | awk {'print $4'}"
    status  = os.popen(mariadb).read()
    return status

def iptables(): 
    iptables = "systemctl status iptables | head -3 | tail -1 | awk '{print $2}'"
    status = os.popen(iptables).read()
    return status



def samba():
    samba = "systemctl | grep smb | awk '{print $4}'"
    status = os.popen(samba).read()
    return status


def ldap():
    ldap = "systemctl | grep ldap | awk '{print $4}'"
    status = os.popen(ldap).read()
    return status






app.config.update(SECRET_KEY=config.SECRET_KEY) # Set Secret Key For Web app


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"



class User(UserMixin):

    def __init__(self, id):
        self.id = id

    def __repr__(self):
        return "%d"% (self.id)


user = User(0)


@app.route("/")
@login_required #this Means for Get dashboard template it shoulb be Login
def loogin():
    return render_template("dashboard.html")

@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def loggin():
    username = request.form["username"]
    password = request.form["password"]
    if username == config.USERNAME and password == config.PASSWORD:
        return render_template("dashboard.html", sestatus=se_status() ,\
            firewalld=firewall_status() , maria = maria_status())
    else:
        return redirect("/login")


# Logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    logging.warning("user logout")
    return redirect("/login")


@app.errorhandler(401)
def page_not_found(e):
    logging.info("401 Error")
    return Response("""
                    <html><center style='background-color:white;'>
                    <h2 style='color:red;'>Login failed</h2>
                    <h1>Error 401</h1>
                    </center></html>""")


@login_manager.user_loader
def load_user(userid):
    return User(userid)


# Main Route

@app.route("/")
def main_page():
    logging.info("Main Page Loading")
    return render_template("dashboard.html", sestatus=se_status() , firewalld=firewall_status() ,\
        maria = maria_status())





@app.route("/search" , methods=["POST"])
def search_all():
    search = request.form["serach_all"]
    cur = connect_db()
    query1 = f"SELECT * FROM malware_url WHERE url LIKE '%{search}%'"
    cur.execute(query1)
    data1 = cur.fetchall()
    cur.close()
    return render_template("search_result.html" , data = data1)
    


@app.route("/av")
def antivirus():
    return render_template("av.html")


@app.route("/av/file" , methods=["POST"])
def antivirus_post():
    dir  = request.form["directory"]
    startTime = time.time()
    files = glob.glob(f"{dir}/**/*.*", recursive=True)
    for file in files:
        with open(file, 'rb') as f:
            header = f.read(32)  # check header
            main_header = str(header.hex())
            if (main_header[0:4] == "4d5a") or (main_header[0:4] == "5a4d"):
                logging.warning("An executable file has been found in system which is potentially infected")
                shutil.move(file, Quarantine)
                t =time.time()
                return Response(f"""<body style='background-color: #2F4F4F;'>
                        <center><h1 style='color:white;'> File Scanning</h1>
                        <h2 style='color:black;'> 'Time taken:', {t} - {startTime}</h2>
                        <h4 style='color:#808080;'> Do you want to Scan with ClamAV?</h4>
                        <a href='/av/clamav'>
                        <button style='background-color: #778899;  border: none;
								color: white;
								padding: 15px 32px;
								text-align: center;
								text-decoration: none;
								display: inline-block;
								font-size: 16px;'>
								Yes											
						</button></a>
      					 <a href='/av/file'>
                              <button style='background-color: #778899;  border: none;
								color: white;
								padding: 15px 32px;
								text-align: center;
								text-decoration: none;
								display: inline-block;
								font-size: 16px;'>
								No											
						</button></a>
						</center>
						</body>""") 
            else:
                return Response(f"""<body style='background-color: #2F4F4F;'>
                        <center><h1 style='color:white;'> Port Scanning</h1>
                        <h2 style='color:black;'> 'Time taken:', {t} - {startTime}</h2>
                        <h4 style='color:#808080;'> Note:Please check ports with netstat for more Details</h4>
                        <a href='/user'>
                        <button style='background-color: #778899;  border: none;
								color: white;
								padding: 15px 32px;
								text-align: center;
								text-decoration: none;
								display: inline-block;
								font-size: 16px;'>
								Home											
						</button></a>
						</center>
						</body>""") 


@app.route("/av/port_scan" , methods=["POST"])
def port_scanner():
    portlist = [20, 21, 22, 23, 25, 53, 80, 110,
                119, 123, 143, 161, 194, 443, 3306, 3389]
    startTime = time.time()
    target = 'localhost'
    t_IP = gethostbyname(target)
    logger.info(Fore.LIGHTYELLOW_EX + "Starting Scan to host;", t_IP)
    logger.info(Fore.LIGHTYELLOW_EX + "scaning for poorts")
    for i in range(1, 65535):
        s = socket(AF_INET, SOCK_STREAM)
        conn = s.connect_ex((t_IP, i))
        if(conn == 0):
            logger.info(Fore.YELLOW+'Port %d: OPEN' % (i,))
            if i in portlist:
                pass
            else:
                logger.warning(Fore.RED+"find Some unusual port")
                logger.warning(Fore.LIGHTYELLOW_EX +
                      "Please check ports with netstat for more details")
                return Response(f"""<body style='background-color: #2F4F4F;'>
                        <center><h1 style='color:white;'> Port Scannong</h1>
                        <h2 style='color:black;'> find Some unusual port {i}</h2>
                        <h4 style='color:#808080;'> Note:Please check ports with netstat for more Details</h4>
                        <a href='/user'>
                        <button style='background-color: #778899;  border: none;
								color: white;
								padding: 15px 32px;
								text-align: center;
								text-decoration: none;
								display: inline-block;
								font-size: 16px;'>
								Home											
						</button></a>
						</center>
						</body>""") 
            s.close()
    t = time.time()
    return Response(f"""<body style='background-color: #2F4F4F;'>
                        <center><h1 style='color:white;'> Port Scanning</h1>
                        <h2 style='color:black;'> 'Time taken:', {t} - {startTime}</h2>
                        <h4 style='color:#808080;'> Note:Please check ports with netstat for more Details</h4>
                        <a href='/user'>
                        <button style='background-color: #778899;  border: none;
								color: white;
								padding: 15px 32px;
								text-align: center;
								text-decoration: none;
								display: inline-block;
								font-size: 16px;'>
								Home											
						</button></a>
						</center>
						</body>""")  


@app.route("/av/system" , methods=["POST"])
def scan_system():
    files = glob.glob(f"{dir}/**/*.*", recursive=True)
    files = glob.glob("/tmp/av/**/*.*" , recursive=True)
    for file in files:
        with open(file,"r") as text:
           r = text.read()
           if (re.search("hack" , r)) or (re.search("encrypt" , r)):
               return Response(f"""<body style='background-color: #2F4F4F;'>
                        <center><h1 style='color:white;'> Port Scanning</h1>
                        <h2 style='color:black;'> 'Time taken:', {t} - {startTime}</h2>
                        <h4 style='color:#808080;'> Note:Please check ports with netstat for more Details</h4>
                        <a href='/user'>
                        <button style='background-color: #778899;  border: none;
								color: white;
								padding: 15px 32px;
								text-align: center;
								text-decoration: none;
								display: inline-block;
								font-size: 16px;'>
								Home											
						</button></a>
						</center>
						</body>""") 
               
@app.route("/home")
def home():
    return render_template("dashboard.html")



if __name__ == "__main__":
    app.run(port=8080,debug=True)

