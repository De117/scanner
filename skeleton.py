#!/usr/bin/python3
# -*- coding: utf-8 -*-

import threading
import math
import time
import io
import sys
import os
import socket
THREAD_NUM = 100


###
#
# Helper functions
#
###

start_time = time.time()

def log(message):
    now = "[%.4f] "%(time.time() - start_time)
    print(now + message, file=sys.stderr)


def load_host_list(filename):
    """Loads the list of hosts to test, looking up the missing parts.

    The file should have each host on its own line,
     in the form of "hostname IP", with at least one of those present.
     Lines that do not conform are ignored.
    """
    try:
        input_file = open(filename, "r")
        lines = [l.strip().split() for l in input_file.readlines()]
        input_file.close()
    except IOError:
        print("Error: could not read in file!", file=sys.stderr)
        sys.exit(-1)

    hosts = [tuple(l) for l in lines if len(l)==2]  # complete records
    rest = [l[0] for l in lines if len(l)==1]       # incomplete records

    IPs = [x for x in rest if is_valid_IP(x)]
    names = list(set(rest)-set(IPs))

    # divide the arrays between threads...
    thread_ips = divide_array(IPs, THREAD_NUM)
    thread_names = divide_array(names, THREAD_NUM)

    # ...and look them up in parallel
    log("Looking up the missing values...")
    threads = []
    for i in range(THREAD_NUM):
        thread = DNS_lookup(i, thread_ips[i], thread_names[i], hosts)
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    return hosts


def is_valid_IP(IP):
    """Returns True if the given IP is in the form '255.255.255.255'"""
    try:
        socket.inet_aton(IP)
        return IP.count(".") == 3
    except OSError:
        return False


def lookup_host_name(IP):
    """Looks up the host name, or a "?" if no hostname can be found."""
    try:
        return socket.gethostbyaddr(IP)[0]
    except socket.herror:
        return "?"


def lookup_host_addr(hostname):
    """Looks up a single host IP address.

    Returns None if it cannot find one."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def divide_array(array, num):
    """Divides the given array into num disjoint ones."""
    ret = []
    for i in range(num):
        N = math.ceil(len(array)/num)
        ret.append( array[i*N : (i+1)*N] )
    return ret


###
#
# The threads for:
#   (reverse) DNS lookup
#   dispatching the hosts to the modules
#
###


class DNS_lookup(threading.Thread):
    def __init__(self, rank, IPs, hostnames, hosts):
        threading.Thread.__init__(self)
        self.rank = rank
        self.IPs = IPs
        self.names = hostnames
        self.hosts = hosts

    def run(self):
        i = 0
        N = len(self.IPs) + len(self.names)
        for ip in self.IPs:
            i += 1
            host = (lookup_host_name(ip), ip)
            self.hosts.append(host)
            print("\t%d: %d/%d" % (self.rank, i, N), file=sys.stderr)

        for name in self.names:
            i += 1
            addr = lookup_host_addr(name)
            # if we can't find the IP, we ignore the record
            if addr:
                self.hosts.append((name, addr))
            print("\t%d: %d/%d" % (self.rank, i, N), file=sys.stderr)


class Scan(threading.Thread):
    def __init__(self, rank, modules, input_hosts, output_file):
        threading.Thread.__init__(self)
        self.rank = rank
        self.input_hosts = input_hosts
        self.output_file = output_file
        self.modules = modules

    def run(self):
        i = 0
        N = len(self.input_hosts)
        for host in self.input_hosts:
            i += 1
            for m in self.modules:
                m.process(host, self.output_file)
            print("\t%d: %d/%d" % (self.rank, i, N), file=sys.stderr)


###
#
# The entry point
#
###

if __name__=="__main__":

    if len(sys.argv) != 2:
        print("Usage: "+sys.argv[0]+" host_list")
        sys.exit(0)

    log("Reading in the host list...")
    # read in the file to process
    host_list = load_host_list(sys.argv[1])

    # find module names
    log("Detecting modules")
    try:
        mod_names = [x for x in os.listdir("./modules")
                        if x[0]!="." and x.endswith(".py")]
        mod_names = [x for x in mod_names if not x.startswith("test")]
        mod_names = [os.path.splitext(x)[0] for x in mod_names]
    except FileNotFoundError:
        print("Error: cannot load modules, or no modules to load!",
                file=sys.stderr)
        sys.exit(-1)

    # load modules
    modules = []
    os.chdir("./modules")
    sys.path.append(".")    # necessary for proper importing
                            # details at mail.python.org/pipermail
                            #  /python-bugs-list/2004-June/023835.html
    for mod_name in mod_names:
        modules.append(__import__(mod_name))

    # divide the hostlist into THREAD_NUM disjoint ones
    thread_hosts = divide_array(host_list, THREAD_NUM)

    # allocate outputs
    thread_streams = [io.StringIO() for i in range(THREAD_NUM)]

    # start the threads
    threads = []
    log("Starting the scan...")
    for i in range(THREAD_NUM):
        thread = Scan(i, modules, thread_hosts[i], thread_streams[i])
        thread.start()
        threads.append(thread)

    # wait for them to finish
    for thread in threads:
        thread.join()

    # join and print the resulting outputs
    s = ""
    for stream in thread_streams:
        stream.seek(0)
        s += stream.read()

    log("Done.")
    print(s)
