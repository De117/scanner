#!/usr/bin/python3
# -*- coding: utf-8 -*-

import threading, io, sys, socket, math
from main import get_logger, THREAD_NUM, PRINT_FREQ

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
    counter = IntWrapper(initial_value=0, total=len(IPs)+len(rest))
    for i in range(THREAD_NUM):
        thread = threading.Thread(
                    target=DNS_lookup,
                    args=(thread_ips[i], thread_names[i], hosts, counter)
                )
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    return hosts


# the thread for (reverse) DNS lookup
def DNS_lookup(IPs, hostnames, hosts, counter):
    for ip in IPs:
        host = (lookup_host_name(ip), ip)
        hosts.append(host)
        counter.inc()

    for name in hostnames:
        addr = lookup_host_addr(name)
        # if we can't find the IP, we ignore the record
        if addr:
            hosts.append((name, addr))
        counter.inc()


class IntWrapper:
    """A threadsafe wrapper for an integer, for use as a counter."""
    def __init__(self, initial_value=0, total=0):
        self.value = initial_value
        self.total = total
        self.lock = threading.Lock()

    def inc(self):
        self.lock.acquire()
        self.value += 1
        if (self.value % PRINT_FREQ == 0 or self.value == self.total):
            log.info("\t%d/%d" % (self.value, self.total))
        self.lock.release()



###
#
# Helper functions
#
###


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

########################################################################


if __name__=="__main__":
    log = get_logger("main")
    if len(sys.argv) != 2:
        print("Usage: "+sys.argv[0]+" host_list")
        sys.exit(0)
    
    log.info("Reading in the host list...")
    # read in the file to process
    host_list = load_host_list(sys.argv[1])
    for hostname, ip in host_list:
        print(hostname+" "+ip)
