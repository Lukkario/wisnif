#!/usr/bin/python2
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import time
import threading
import os
import sys
import sqlite3
import datetime

def proc(p):
        if( p.haslayer(Dot11ProbeReq) ):
                global con
                ssid=p[Dot11Elt].info
                ssid=ssid.decode('utf-8','ignore')
                if ssid == "":
                        ssid="<BROADCAST>"
                p.addr1 = str(p.addr1)
                p.addr2 = str(p.addr2)
                cursor = con.execute("SELECT COUNT(*) FROM REQ WHERE MACC=(?) AND MACS=(?) AND SSID=(?)", (p.addr2, p.addr1, ssid))
                cou = cursor.fetchone()[0]
                if cou == 0:
                    con.execute("INSERT INTO REQ (MACC, MACS, SSID, TIME_SEEN) VALUES(?, ?, ?, ?)", (p.addr2, p.addr1, ssid, datetime.datetime.now()))
                    con.commit()
                if cou == 1:
                    cursor = con.execute("SELECT TIME_SEEN FROM REQ WHERE MACC=(?) AND MACS=(?) AND SSID=(?)", (p.addr2, p.addr1, ssid))
                    t = cursor.fetchone()[0]
                    if datetime.datetime.now() - datetime.datetime.strptime(t, '%Y-%m-%d %H:%M:%S.%f') > datetime.timedelta(minutes=1):
                        con.execute("UPDATE REQ SET TIME_SEEN = (?) WHERE MACC= (?) AND MACS= (?) AND SSID= (?)", (datetime.datetime.now(),p.addr2, p.addr1, ssid))
                        con.commit()

def sn():
    global con
    if not os.path.isfile(date+".db"):
        con = sqlite3.connect(date+".db")
        con.execute("CREATE TABLE REQ (ID integer primary key not null, MACC text, MACS text, SSID text, TIME_SEEN timestamp)")
        con.commit()

    else:
        con = sqlite3.connect(date+".db")
    sniff(iface=mon, prn=proc, store=0)

def sn_th():
    t = threading.Thread(target=sn)
    t.daemon = True
    t.start()

if len(sys.argv) < 2:
    print("Usage: wifi.py <iface> ")
    sys.exit(1)

mon = sys.argv[1]
date = str(datetime.datetime.now().date())

sn_th()
os.system("reset")
con2 = sqlite3.connect(date+".db")
head = "    CLIENT MAC    |       AP MAC      |            TIME            |            SSID            "
try:
    while True:
        cmd = input("\033[92mshell> \033[0m")
        if cmd == "show all":
            os.system("clear")
            print('\033[91m')
            print(head)
            show = con2.execute("SELECT * FROM REQ")
            for row in show:
                print(row[1] + " | " + row[2] + " | " + row[4] + " | " + row[3])
            print('\033[0m')

        elif cmd == "show all by time":
            os.system("clear")
            print('\033[91m')
            print(head)
            show = con2.execute("SELECT * FROM REQ ORDER BY TIME_SEEN ASC")
            for row in show:
                print(row[1] + " | " + row[2] + " | " + row[4] + " | " + row[3])
            print('\033[0m')

        elif cmd == "show ignore bc":
            os.system("clear")
            br = "<BROADCAST>"
            print('\033[91m')
            print(head)
            show = con2.execute("SELECT * FROM REQ WHERE SSID != (?) ORDER BY TIME_SEEN ASC", (br,))
            for row in show:
                print(row[1] + " | " + row[4] + " | " + row[3])
            print('\033[0m')

        elif cmd == "help":
            os.system("clear")
            print("""
                show all            shows MACC MACS SSID TIME
                show all by time    shows all oredered by TIME ascending
                show ignore bc      shows all excluding where SSID = <BROADCAST>
            """)

        elif cmd == "exit" or cmd == "quit":
            break

        else:
            print("Command " + cmd + " not found")

except KeyboardInterrupt:
    pass
