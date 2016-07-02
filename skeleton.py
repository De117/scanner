#!/usr/bin/python3
# -*- coding: utf-8 -*-

import threading
import math
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


def init_list(raw_list):
    """Looks up the missing domains/IPs.

    Takes a list of domains xor IPs,
    and returns a list of (domain, IP) tuples."""
    ret = []
    for el in raw_list:
        if is_valid_IP(el):
            # for IPs, we look up the host name
            ret.append((lookup_host_name(el), el))
        else:
            # for domains, we look up the IP
            addr = lookup_host_addr(el)
            # if we can't find it, we throw it out
            if addr:
                ret.append((el, addr))
    return list(set(ret))


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

###
#
# The thread dispatching the hostnames/IPs to the modules
#
###


class Dispatch(threading.Thread):
    def __init__(self, rank, modules, input_hosts, output_file):
        threading.Thread.__init__(self)
        self.rank = rank
        self.input_hosts = input_hosts
        self.output_file = output_file
        self.modules = modules

    def run(self):
        i = 0
        for host in self.input_hosts:
            i += 1
            for m in self.modules:
                m.process(host, self.output_file)
            #if (i%10==0) or (i==len(self.input_hosts)):
            print("%d: %d/%d" % (self.rank, i, len(self.input_hosts)),
                    file=sys.stderr)


###
#
# The actual script
#
###

if __name__=="__main__":

    if len(sys.argv) != 2:
        print("Usage: "+sys.argv[0]+" input_file")
        sys.exit(0)

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
        mod_names = [x for x in os.listdir("./modules")
                        if x[0]!="." and x.endswith(".py")]
        mod_names = [x for x in mod_names if not x.startswith("test")]
        mod_names = [os.path.splitext(x)[0] for x in mod_names]
    except FileNotFoundError:
        print("Error: cannot load modules, or no modules to load!")
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
    thread_hosts = []
    for i in range(THREAD_NUM):
        N = math.ceil(len(host_list)/THREAD_NUM)
        thread_hosts.append( host_list[i*N : (i+1)*N] )

    # allocate outputs
    thread_streams = [io.StringIO() for i in range(THREAD_NUM)]

    # start the threads
    threads = []
    print("Starting the threads...", file=sys.stderr)
    for i in range(THREAD_NUM):
        thread = Dispatch(i, modules, thread_hosts[i], thread_streams[i])
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

    print(s)
