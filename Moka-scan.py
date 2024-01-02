#!/usr/bin/python3
# Moka-scan - Multi-threader Port Scanner
# A project by The Mohamed Ragab
# v1.0
# https://github.com/Mohamed-A-Ragab/Moka-Scan
# Licensed under GNU GPLv3 Standards.  https://www.gnu.org/licenses/gpl-3.0.en.html

import socket
import os
import threading
import sys
from queue import Queue
from datetime import datetime

logo = """
  __  __ 
 |  \/  | ___  
 | |\/| |/ _ \ 
 | |  | | (_) |
 |_|  |_|\___/  Scan
 v1.0
         
"""

author_info = "Author: m.batistuta666@gmail.com"

def moka_scan(target):
    socket.setdefaulttimeout(0.30)
    print_lock = threading.Lock()
    discovered_ports = []

    print("-" * 60)
    print(logo)
    print(author_info)
    print("-" * 60)

    try:
        t_ip = socket.gethostbyname(target)
    except (UnboundLocalError, socket.gaierror):
        print("\n[-] Invalid format. Please use a correct IP or web address [-]\n")
        sys.exit()

    print("-" * 60)
    print("Scanning target " + t_ip)
    print("Time started: " + str(datetime.now()))
    print("-" * 60)
    t1 = datetime.now()

    def portscan(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            portx = s.connect((t_ip, port))
            with print_lock:
                print("Port {} is open".format(port))
                discovered_ports.append(str(port))
            portx.close()
        except (ConnectionRefusedError, AttributeError, OSError):
            pass

    def threader():
        while True:
            worker = q.get()
            portscan(worker)
            q.task_done()

    q = Queue()

    for x in range(200):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()

    for worker in range(1, 65536):
        q.put(worker)

    q.join()

    t2 = datetime.now()
    total = t2 - t1
    print("Port scan completed in " + str(total))
    print("-" * 60)
    print("Moka-scan recommends the following Nmap scan:")
    print("*" * 60)
    print("nmap -p{ports} -sV -sC -T4 -Pn -oA {ip} {ip}".format(ports=",".join(discovered_ports), ip=target))
    print("*" * 60)
    nmap = "nmap -p{ports} -sV -sC -T4 -Pn -oA {ip} {ip}".format(ports=",".join(discovered_ports), ip=target)
    t3 = datetime.now()
    total1 = t3 - t1

    def automate():
        choice = '0'
        while choice == '0':
            print("Would you like to run Nmap or quit to terminal?")
            print("-" * 60)
            print("1 = Run suggested Nmap scan")
            print("2 = Run another Moka-scan")
            print("3 = Exit to terminal")
            print("-" * 60)
            choice = input("Option Selection: ")
            if choice == "1":
                try:
                    print(nmap)
                    os.mkdir(target)
                    os.chdir(target)
                    os.system(nmap)
                    t3 = datetime.now()
                    total1 = t3 - t1
                    print("-" * 60)
                    print("Combined scan completed in " + str(total1))
                    print("Press enter to quit...")
                    input()
                except FileExistsError as e:
                    print(e)
                    exit()
            elif choice == "2":
                main()
            elif choice == "3":
                sys.exit()
            else:
                print("Please make a valid selection")
                automate()

    automate()

if __name__ == '__main__':
    target = input("Enter your target IP address or URL here: ")
    moka_scan(target)
