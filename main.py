#!/usr/bin/python3
# -*- coding: utf-8 -*-

import threading
import math
import time
import io
import sys
import os
import socket
import logging
THREAD_NUM = 400
PRINT_FREQ = 10


###
#
# Helper functions
#
###

class RelativeFormatter(logging.Formatter):
    """A custom formatter.
    
    Adds elapsed time (in seconds.milliseconds) in front of the message.
    """
    def format(self, record):
        ret = super().format(record)
        return "[%.4f] "%(record.relativeCreated/1000) + ret


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
    log.info("Looking up the missing values...")
    threads = []
    counter = IntWrapper(value=0, total=len(IPs)+len(rest))
    lock = threading.Lock()
    for i in range(THREAD_NUM):
        thread = DNS_lookup(thread_ips[i], thread_names[i],
                            hosts, lock, counter)
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
    def __init__(self, IPs, hostnames, hosts, lock, counter):
        threading.Thread.__init__(self)
        self.IPs = IPs
        self.names = hostnames
        self.hosts = hosts
        self.lock = lock
        self.counter = counter

    def inc(self):
        self.lock.acquire()
        self.counter.inc()
        self.lock.release()

    def run(self):
        for ip in self.IPs:
            host = (lookup_host_name(ip), ip)
            self.hosts.append(host)
            self.inc()

        for name in self.names:
            addr = lookup_host_addr(name)
            # if we can't find the IP, we ignore the record
            if addr:
                self.hosts.append((name, addr))
            self.inc()


class Scan(threading.Thread):
    def __init__(self, modules, input_hosts, output_file, lock, counter):
        threading.Thread.__init__(self)
        self.input_hosts = input_hosts
        self.output_file = output_file
        self.modules = modules
        self.lock = lock
        self.counter = counter

    def inc(self):
        self.lock.acquire()
        self.counter.inc()
        self.lock.release()

    def run(self):
        N = len(self.input_hosts)
        for host in self.input_hosts:
            for m in self.modules:
                m.process(host, self.output_file)
            self.inc()


class IntWrapper:
    """A wrapper for an integer, for use as a counter."""
    def __init__(self, value=0, total=0):
        self.value = value
        self.total = total

    def inc(self):
        self.value += 1
        if (self.value % PRINT_FREQ == 0 or self.value == self.total):
            log.info("\t%d/%d" % (self.value, self.total))


###
#
# The entry point
#
###

if __name__=="__main__":

    if len(sys.argv) != 2:
        print("Usage: "+sys.argv[0]+" host_list")
        sys.exit(0)

    # create and initialize logger
    log = logging.getLogger("main") # create logger @ info lvl
    log.setLevel(logging.INFO)
    sh = logging.StreamHandler()    # create streamhandler @ info lvl
    sh.setLevel(logging.INFO)
    sh.setFormatter(RelativeFormatter())    # add custom formatter
    log.addHandler(sh)

    log.info("Reading in the host list...")
    # read in the file to process
    host_list = load_host_list(sys.argv[1])

    # find module names
    log.info("Detecting modules")
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
    lock = threading.Lock()
    counter = IntWrapper(0, len(host_list))
    log.info("Starting the scan...")
    for i in range(THREAD_NUM):
        thread = Scan(modules, thread_hosts[i], thread_streams[i],
                        lock, counter)
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

    log.info("Done.")
    print(s)
