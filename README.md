# Moka-scan 
### Multi-threaded Python Port Scanner with Nmap integration for use on Linux or Windows

Moka-scan is a script written in Python3 that allows multi-threaded port scanning.  The program is interactive and simply requires you to run it to begin.  Once started, you will be asked to input an IP address or a FQDN as Moka-scan does resolve hostnames.  A full port scan can take as little as 15 seconds, but at max should take less than 1 minute 30 seconds depending on your internet connection.

## Requirements
Python3 must be installed on your system in order to function
Pip3 for installation via PyPi repository

## Installation
**Installation via Pip**

```bash 
pip3 install threader3000
```

Run by typing:
```bash
threader3000
```
**Install via Git**

```bash
git clone https://github.com/Mohamed-A-Ragab/Moka-Scan #to save the program to your machine, or utilize the download option
```

Change permissions for the file Moka-scan.py

```bash
sudo chmod +x Moka-scan.py
```

You can add Moka-scan to run from any directory by adding a symbolic link:

```bash
sudo ln -s $(pwd)/Moka-scan.py /usr/local/bin/Moka-scan
```

## FAQ

**Can I use this tool to scan Facebook or other websites I don't have permission to scan?**

*No. That would be illegal.  This tool is under a free license for use, however it is up to the user to observe all applicable laws and appropriate uses for this tool.  The creator does not condone, support, suggest, or otherwise promote unethical or illegal behavior.  You use this tool at your own risk, and under the assumption that you are utilizing it against targets and infrastructure to which you have permission to do so.  Any use otherwise is at your peril and against the terms of use for the tool.*

**Will you please integrate multiple IP addresses and different scanning tools into Moka-scan, making it an all-in-one automated scanner?**

Not as of current.  If you want a tool like that, I suggest [AutoEnum](https://github.com/Gr1mmie/autoenum).

This tool, when used correctly, can help you to pass the OSCP exam. The OSCP is all about time management and enumeration. I give you a tool that is quick and conducts good single target scanning.  It's up to you to use it.

**Can I make pull requests with changes that I think are best for Moka-scan?**

You can, but these will likely be denied. Moka-scan is a tool I wrote to meet my needs in the field, and I've simply shared it with everyone. If you find an issue that causes significant issues, please report it, however changes to code on how a user thinks it should be better written or how the user feels it should function will be denied.  
