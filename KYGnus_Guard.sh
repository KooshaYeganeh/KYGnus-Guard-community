#!/bin/bash



<<username
Enter Your Youser and App Files will be in This User
username

username="" # Enter username


cd /home/$USER/App/.KYGnus_Guard_Community

source venv/bin/activate

<<python
Note : if You User Debian Base systems Like Ubunjtu or Lubuntu or Others
Yoy should Change python with python3 tu Run App.in RedHat Base systems Like
Fedora python command Runs Default Python3
python

python app.py

