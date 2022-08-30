from crypt import methods
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
import paramiko




username = getpass.getuser()


appdir = os.path.join(f"/home/{username}/KYGnus_Guard_community")
os.makedirs(appdir,exist_ok=True)

Log = os.path.join(f"/home/{username}/KYGnus_Guard_community/Log")
os.makedirs(Log,exist_ok=True)


Quarantine = os.path.join(f"/home/{username}/KYGnus_Guard_community/Quarantine")
os.makedirs(Quarantine,exist_ok=True)



app = Flask(__name__)



logging.basicConfig(filename=f"{appdir}/Log/KYGnus_Guard.log",
                    format='%(asctime)s %(message)s',
                    filemode='w')

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


logger.info(Fore.LIGHTRED_EX + """
            
██╗  ██╗██╗   ██╗ ██████╗ ███╗   ██╗██╗   ██╗███████╗       ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ 
██║ ██╔╝╚██╗ ██╔╝██╔════╝ ████╗  ██║██║   ██║██╔════╝      ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
█████╔╝  ╚████╔╝ ██║  ███╗██╔██╗ ██║██║   ██║███████╗█████╗██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██╔═██╗   ╚██╔╝  ██║   ██║██║╚██╗██║██║   ██║╚════██║╚════╝██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
██║  ██╗   ██║   ╚██████╔╝██║ ╚████║╚██████╔╝███████║      ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝       ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ 
                                                                                                     
            
            
            """)




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



def netwok_manager():
    net = "systemctl | grep NetworkManager | awk '{print $4}' | tail -1"
    status = os.popen(net).read()
    return status

def clam_status():
    clamav = "systemctl | grep clamav | awk {'print $4'}"
    status  = os.popen(clamav).read()
    if status:
        return status
    else:
        return "Not Found"


def mariadb_malware_url():
    db = connect_db()
    cur = db.cursor()
    query = "SELECT * FROM malware_url"
    data = cur.execute(query)
    number = int(data)
    return number



def app_disk_usage():
    usage = os.popen(f"du -h {appdir} | tail -1").read()
    filter = usage.split()
    return filter[0]


def num_quarantine():
    files = glob.glob("/home/koosha/Desktop/**/*.*" , recursive=True)
    num = len(files)
    return num

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
            firewalld=firewall_status() , maria = maria_status() , malware_url=mariadb_malware_url(),\
                app_usage = app_disk_usage())
    else:
        return redirect("/login")


# Logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    logger.warning("user logout")
    return redirect("/login")


@app.errorhandler(401)
def page_not_found(e):
    logger.info("401 Error")
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
    logger.info("Main Page Loading")
    return render_template("dashboard.html", clamav=clam_status(), sestatus=se_status() , firewalld=firewall_status() ,\
        maria = maria_status(),num_quarantine = num_quarantine())

        





@app.route("/search/all" , methods=["POST"])
def search_all():
    search = request.form["serach_all"]
    db = connect_db()
    cur = db.cursor()
    query1 = f"SELECT * FROM malware_url WHERE url LIKE '%{search}%'"
    cur.execute(query1)
    data1 = cur.fetchall()
    cur.close()
    return render_template("search_url_table.html" , data = data1)
    


# Antivirus

@app.route("/av")
def antivirus():
    return render_template("Antivirus.html", clamav=clam_status(), sestatus=se_status() , firewalld=firewall_status() ,\
        maria = maria_status(),num_quarantine = num_quarantine())




@app.route("/av/kyguard" , methods=["POST"])
def antivirus_post():
    try:
        dir = request.form["path"]
        files = glob.glob(f"{dir}/**/*.*", recursive=True)
        for file in files:
            with open(file, 'rb') as f:
                header = f.read(32)  # check header
                main_header = str(header.hex())
                if (main_header[0:4] == "4d5a") or (main_header[0:4] == "5a4d"):
                    logger.warning(Fore.RED + "An executable file has been found in system which is potentially infected")
                    shutil.move(file, Quarantine)
        allfiles = glob.glob(f"{dir}/**/*.txt", recursive=True)
        for txtfile in allfiles:
            with open(txtfile,"r") as text:
                r = text.read()
                if (re.search("hack" , r)) or (re.search("encrypt" , r)):
                    shutil.move(txtfile,Quarantine)
                    logger.warning(Fore.RED + "Malicious Files Detected and Quarantined")
        pythonfiles = glob.glob(f"{dir}/**/*.py" , recursive=True)
        for pfiles in pythonfiles:
            with open(pfiles,"r") as python:
                 py = python.read()
                 if (re.search("connect",py)) or (re.search("encrypt",py)) or (re.search("remote",py)) or (re.search("anonymous",py)):
                     shutil.move(py,Quarantine)
                     logger.warning(Fore.RED + "Malicious python Script Detected and Quarantined")
        rubyfiles = glob.glob(f"{dir}/**/*.rb" , recursive=True)
        for rubyfile in rubyfiles:
            with open(rubyfile,"r") as ruby:
                 rb = ruby.read()
                 if (re.search("connect",rb)) or (re.search("encrypt",rb)) or (re.search("remote",rb)) or (re.search("anonymous",rb)):
                     shutil.move(rb,Quarantine)
                     logger.warning(Fore.RED + "Malicious Ruby Script Detected and Quarantined")
        perlfiles = glob.glob(f"{dir}/**/*.pl" , recursive=True)
        for perlscript in perlfiles:
            with open(perlscript,"r") as perl:
                pl = perl.read()
                if (re.search("connect",pl)) or (re.search("encrypt",pl)) or (re.search("remote",pl)) or (re.search("anonymous",pl)):
                    shutil.move(pl,Quarantine)
                    logger.warning(Fore.RED + "Malicious Perl Script Detected and Quarantined")
        javascripts = glob.glob(f"{dir}/**/*.js" , recursive=True)
        for javascript in javascripts:
            with open(javascript,"r") as java:
                js = java.read()
                if (re.search("connect",js)) or (re.search("encrypt",js)) or (re.search("remote",js)) or (re.search("anonymous",js)):
                    shutil.move(js,Quarantine)
                    logger.warning(Fore.RED + "Malicious javascript  Detected and Quarantined")
        webfiles = glob.glob("/var/www/**/*.*" , recursive=True)
        for webfile in webfiles:
            with open(webfile,"r") as web:
                w = web.read()
            if ((re.search("\/usr" , w)) and ((re.search("python" , w)))) or (webfile.endswith(".py")):
                shutil.move(webfile,Quarantine)
                logger.warning(Fore.RED + "Malicious python Script Detected and Quarantined")
            if ((re.search("\/usr" , w)) and ((re.search("perl" , w)))) or (webfile.endswith(".pl")):
                shutil.move(webfile,Quarantine)
                logger.warning(Fore.RED + "Malicious Perl Script Detected and Quarantined")
            if ((re.search("\/usr" , w)) and ((re.search("ruby" , w)))) or (webfile.endswith(".rb")):
                shutil.move(webfile,Quarantine)
                logger.warning(Fore.RED + "Malicious Ruby Script Detected and Quarantined")  
        return Response(f"""<!DOCTYPE html>
								<html lang="en">

								<head>
									<meta charset="UTF-8">
									<meta http-equiv="X-UA-Compatible" content="IE=edge">
									<meta name="viewport" content="width=device-width, initial-scale=1.0">
									<link rel="stylesheet" href="./static/bootstrap.min.css">
									<script src="./static/bootstrap.min.js"></script>
									<title>KYGnus Guard Response</title>
								</head>

								<body style="margin-top: 50px;">

									<div class="containter">
										<div class="row">
											<div class="col-md-12" style="text-align: center;">
												<h1>KYGnus Guard</h1>
									<h2 style="color: black;">Directory Scaned Successfully</h2>
									<p> Details will be in Log Files and Quarantine Files are in {appdir}/Quarantine Folder</p>
								<img src='./static/KYguard.png' alt='kyguard' width="250" height="250">
        						<h3 style="color: black;"> Do You want to Scan With clamAV?</h3>
								<div>
								<a href='/av/clamav'>
												<button style='background-color: #778899;  border: none;
													color: black;
													padding: 10px 40px;
													margin: 40px;
													text-align: center;
													text-decoration: none;
													display: inline-block;
													font-size: 16px;'>
																								
											yes</button></a>
											</form>
									<a href='/av'>
												<button style='background-color: #778899;  border: none;
													color: black;
													padding: 10px 40px;
													margin: 40px;
													text-align: center;
													text-decoration: none;
													display: inline-block;
													font-size: 16px;'>
																								
											No</button></a>
											</form>

								</div>
							</div>
						</div>

					</body>

					</html>""")

    except:
        return render_template("Error.html")





@app.route("/av/port_scan" , methods=["POST"])
def port_scanner():
	try:
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

	except:
		return render_template("Error.html")





@app.route("/av/clamav")
def clamav():
    return render_template("clamAV.html")


@app.route("/av/clamav" , methods=["POST"])
def port_clamav():
    logger.warning(Fore.RED + "User Start to Scan system with clamAV")
    clamdir = request.form["clamdir"]
    clamav = f"clamscan --infected --recursive --remove {clamdir}"
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(config.ssh_host,config.ssh_port,config.ssh_username,config.ssh_password)
    stdin,stdout,stderr = ssh.exec_command(clamav)
    stdin.close()
    lines = stdout.readlines()
    seresp = ''.join(lines).split()
    for sres in seresp:
        logger.log(Fore.RED + f"{sres}")
    return Response(f"""<html style='background-color:black;'><body>
                    <center>
                    <h3 style='color: #B22222;'> ClamAV </h3>
                    <h1 style='color: #B22222 ; '> Successfull Scan Scan with clamAV </h1>
                    <p style='color: #B22222 ; '> Note:check Results in Log File in {appdir}</p>
                    <p style='color: #B22222 ; '> Note: This app Scan Directory with clamAV <code> Remote System</code> so clamAV should be Install on Remote system</p>
					 <img src='./static/clamav.png' alt='clamAV' width="250" height="250">
					<div style='margin-top:20px;'>
					<a href='/av/clamav'><button class='return' style='background-color:red;
						border: none;
						color: white;
						padding: 10px 32px;
						text-align: center;
						text-decoration: none;
						display: inline-block;
						font-size: 16px;
						margin: 4px 2px;
						transition-duration: 0.4s;
						cursor: pointer;'>
					return</button></a>

    		 </div>
     		</center>
     	</body>
      </html>
    """)        


@app.route("/network")
def network():
    return render_template("network.html", sestatus=se_status() ,\
            firewalld=firewall_status() ,network = netwok_manager(),ldap = ldap())



@app.route("/network/url")
def network_search_url():
    return render_template("search_url.html", sestatus=se_status() ,\
            firewalld=firewall_status() ,network = netwok_manager(),ldap = ldap())


@app.route("/network/url" , methods=["POST"])
def search_url():
    search = request.form["serach_url"]
    info  = "Your Entered URL is Malicious [ DANGER ]"
    db = connect_db()
    cur = db.cursor()
    query1 = f"SELECT * FROM malware_url WHERE url LIKE '%{search}%'"
    cur.execute(query1)
    data1 = cur.fetchall()
    cur.close()
    if data1:
        return render_template("search_url_table.html" , data = data1 , info = info )
    else:
        return render_template("search_url_table.html" , data = data1 , info = "Nothing Found !!!" )
        




@app.route("/system")
def system():
    return render_template("systemfile.html")


@app.route("/system/permcheck" , methods=["POST"])
def system_permissions():
    thistime = time.ctime()
    usr_bin = os.popen("sudo find /usr/sbin -type f -exec sha256sum {} \; > /tmp/perm/usr_bin.txt").read()
    usr_sbin = os.popen("sudo find /usr/bin -type f -exec sha256sum {} \; > /tmp/perm/usr_sbin.txt").read()
    etc = os.popen("sudo find /etc -type f -exec sha256sum {} \; > /tmp/perm/etc.txt").read()
    sha = os.popen("sha256sum /tmp/perm/*").read()
    with open ("/tmp/hash.txt" , "w") as h:
        h.write("=================================<< KYGnus >>===================================\n\n")
        h.write(f"----------------- sha256sum Time of Calculation:{thistime}  ------------------\n")
        h.write(f"{sha}")
        h.close()
    return Response(f"""<!DOCTYPE html>
								<html lang="en">

								<head>
									<meta charset="UTF-8">
									<meta http-equiv="X-UA-Compatible" content="IE=edge">
									<meta name="viewport" content="width=device-width, initial-scale=1.0">
									<link rel="stylesheet" href="./static/bootstrap.min.css">
									<script src="./static/bootstrap.min.js"></script>
									<title>KYGnus Guard Response</title>
								</head>

								<body style="margin-top: 50px;">

									<div class="containter">
										<div class="row">
											<div class="col-md-12" style="text-align: center;">
												<h1>KYGnus Guard</h1>
									<h2 style="color: black;">Directory Scaned Successfully</h2>
                 						<p > The permissions of /usr/bin and /usr/sbin and /etc Directories calculated and save in /tmp/perm Directorie's.</p>
								<p >if You Want to save This Files Move Them From /tmp Directory</p>
								<img src='./static/KYguard.png' alt='KYguard' width="250" height="250">

								<div>
								<a href='/av/clamav'>
												<button style='background-color: #778899;  border: none;
													color: black;
													padding: 10px 40px;
													margin: 40px;
													text-align: center;
													text-decoration: none;
													display: inline-block;
													font-size: 16px;'>
																								
											Return</button></a>
											</form>

								</div>
							</div>
						</div>

					</body>

					</html>""")



@app.route("/vulnerability")
def vul():
    with open ("/tmp/vulcheck.txt" , "w") as vul:
        """ This Scope of code check mariaDB configs for Security Reasons"""
        vul.write("================================== MariaDB =================================\n\n")
        mariadb_port_ok = os.popen("cat /etc/my.cnf.d/mariadb-server.cnf | egrep '^port' ").read()
        mariadb_port_false = os.popen("cat /etc/my.cnf.d/mariadb-server.cnf | egrep '^#port' ").read()
        mariadb_bind_ok = os.popen("cat /etc/my.cnf.d/mariadb-server.cnf | egrep '^bind'").read()
        mariadb_bind_false = os.popen("cat /etc/my.cnf.d/mariadb-server.cnf | egrep '^#bind' ").read()
        mariadb_username = os.popen("cat /etc/my.cnf | grep user").read()
        mariadb_password = os.popen("cat /etc/my.cnf | grep password").read()
        mariadb_max_allowed_packet = os.popen("cat /etc/my.cnf.d/mariadb-server.cnf | grep 'max_allowed_packet'").read()
        mariadb_max_connections = os.popen("cat /etc/my.cnf.d/mariadb-server.cnf | grep 'max_connections'").read()
        mariadb_max_user_connections = os.popen("cat /etc/my.cnf.d/mariadb-server.cnf | grep 'max_user_connections'").read()
        ssh_service = os.popen("systemctl status sshd | grep running").read()
        fail2ban = os.popen("find /usr/bin -type f -iname faul2ban").read()
        apache = os.popen("systemctl status apache | grep running").read()
        nginx = os.popen("systemctl status nginx | grep running").read()
        if (mariadb_port_ok):
            vul.write(Fore.CYAN + "port config of /etc/my.cnf.d/mariadb-server.cnf is [ OK ]\n")
        elif (mariadb_port_false):
            vul.write(Fore.RED + "check port config But this Line is commented and port is Default [ DANGER ]\n")
        else:
                vul.write(Fore.YELLOW + "No port config Detected [ WARNING ]\n")
        if (mariadb_bind_ok):
            vul.write(Fore.CYAN + "bind Address config [ OK ]\n")
        elif (mariadb_bind_false):
            vul.write(Fore.RED + "check bind config But this Line is commented and bind is Default [ DANGER ]\n")
        if (mariadb_username) or (mariadb_password):
            vul.write(Fore.RED + "You set username or password on config File.This is out of Security Rules[ DANGER ]\n")
        else:
            vul.write(Fore.CYAN + "No Username and Password Detected [ OK ]\n")
        if (mariadb_max_allowed_packet):
            vul.write(Fore.CYAN + "max_allowed packet config is [ OK ]\n")
        else:
            vul.write(Fore.RED + "No max_allowed_packet Address config Detected [ DANGER ]\n")
        if (mariadb_max_allowed_packet):
            vul.write(Fore.CYAN + "max_allowed packet config is [ OK ]\n")
        else:
            vul.write(Fore.RED + "No max_allowed_packet Address config Detected [ DANGER ]\n")
        if (mariadb_max_connections):
            vul.write(Fore.CYAN + "MariaDB Max connections Set in config File [ OK ]\n")
        else:
            vul.write(Fore.RED + "MariaDB Max connections Not Set in config File [ DANGER ]\n")
        if (mariadb_max_user_connections):
            vul.write(Fore.CYAN + " MariaDB Max user Connection set in config File [ OK ]\n")
        else:
            vul.write(Fore.RED + "MariaDB Max user Connection Not set in config File [ DANGER ]\n")
        if ssh_service:
            if fail2ban:
                vul.write(Fore.CYAN + "You Install Fail2ban 2 prevent ssh Bruteforce attack [ OK ]\n")
            else:
                vul.write(Fore.RED + "Fail2ban Service Not Install On Your system instead of ssh Service Active and Running on Your system [ Danger ]\n")
        if apache or nginx:
            vul.write(Fore.YELLOW  + "You should set Rule for iptables for 80 port [ WARNING ]\n")
        return Response(f"""<!DOCTYPE html>
								<html lang="en">

								<head>
									<meta charset="UTF-8">
									<meta http-equiv="X-UA-Compatible" content="IE=edge">
									<meta name="viewport" content="width=device-width, initial-scale=1.0">
									<link rel="stylesheet" href="./static/bootstrap.min.css">
									<script src="./static/bootstrap.min.js"></script>
									<title>KYGnus Guard Response</title>
								</head>

								<body style="margin-top: 50px;">

									<div class="containter">
										<div class="row">
											<div class="col-md-12" style="text-align: center;">
												<h1>KYGnus Guard</h1>
									<h2 style="color: black;">system Scaned Successfully</h2>
                 						<p > Vulnerability checked and results Saved in Text File in /tmp</p>
								<p >if You Want to save The File Move it From /tmp Directory</p>
								<img src='./static/KYguard.png' alt='KYguard' width="250" height="250">

								<div>
								<a href='/vulnerability'>
												<button style='background-color: #778899;  border: none;
													color: black;
													padding: 10px 40px;
													margin: 40px;
													text-align: center;
													text-decoration: none;
													display: inline-block;
													font-size: 16px;'>
											Return</button></a>
											</form>

								</div>
							</div>
						</div>

					</body>

					</html>""")



    

@app.route("/home")
def home():
    return render_template("dashboard.html")



@app.route("/Downloads")
def downloads():
    return render_template("Downloads.html")


@app.route("/support")
def support():
    return render_template("support.html")

if __name__ == "__main__":
    app.run(port=8080,debug=True)

