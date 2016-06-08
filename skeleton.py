#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
import os
import socket

###
#
# Helper functions
#
###

# takes a list of domains and IPs, and
#  returns a list of unique (domain, IP) tuples
def init_list(raw_list):
    ret = []
    for el in raw_list:
        if is_valid_IP(el):
            # for IPs, we look up the host name
            ret.append( (lookup_host_name(el), el) )
        else:
            # for domains, we look up the IP
            addr = lookup_host_addr(el)
            # if we can't find it, we throw it out
            if addr:
                ret.append((el, addr))
    return list(set(ret))

# returns true if given IP is in the form "255.255.255.255"
def is_valid_IP(IP):
    try:
        socket.inet_aton(IP)
        return IP.count(".")==3
    except OSError:
        return False

# looks up the host name, or a placeholder name if none can be found
def lookup_host_name(IP):
    try:
        return socket.gethostbyaddr(IP)[0]
    except socket.herror:
        return "?"

# looks up a single host IP address; returns None if it cannot find one
def lookup_host_addr(hostname):
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

if len(sys.argv) != 2:
    print("Usage: "+sys.argv[0]+" input_file")
    sys.exit(0)


###
#
# The actual script
#
###

# read in the file to process
try:
    input_file = open(sys.argv[1], "r")
    lines = [l.strip() for l in input_file.readlines()]
    input_file.close()
except IOError:
    print("Error: could not read in file!")
    sys.exit(-1)

# look up necessary addresses/hostnames
host_list = init_list(lines)


# find module names
try:
    mod_names = [x for x in os.listdir("./modules") if x[0]!="." and x.endswith(".py")]
    mod_names = [x for x in mod_names if not x.startswith("test")]
    mod_names = [os.path.splitext(x)[0] for x in mod_names]
except FileNotFoundError:
    print("Error: cannot load modules, or no modules to load!")
    sys.exit(-1)

# load modules
modules = []
os.chdir("./modules")
sys.path.append(".") # necessary for proper importing
                     # details at mail.python.org/pipermail
                     #  /python-bugs-list/2004-June/023835.html
for mod_name in mod_names:
    modules.append( __import__(mod_name) )

# run the modules
for host in host_list:
    for m in modules:
        m.process(host, sys.stdout)
