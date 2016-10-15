#!/usr/bin/python3
# -*- coding: utf-8 -*-

import threading
import queue
import math
import time
import io
import sys
import os
import importlib
import socket
import logging
import sqlite3
import argparse
from options import options
module_names = ["sslmodule"]

number_of_hosts = None

file_loaded = threading.Event()
SUSPEND = False

class RelativeFormatter(logging.Formatter):
    """A custom formatter.
    
    Adds elapsed time (in seconds.milliseconds) in front of the message.
    """
    def format(self, record):
        ret = super().format(record)
        return "[%.4f] "%(record.relativeCreated/1000) + ret


class IntWrapper:
    """A threadsafe wrapper for an integer, for use as a counter."""
    def __init__(self, initial_value=0, total=0, print_frequency=None):
        self.value = initial_value
        self.total = total
        self.print_freq = print_frequency
        self.lock = threading.Lock()

    def inc(self):
        with self.lock:
            self.value += 1
            if self.print_freq and (self.value % self.print_freq == 0
                                    or self.value == self.total):
                log.info("\t%d/%d" % (self.value, self.total))


def get_logger(name):
    """Creates and initializes the logger."""
    log = logging.getLogger(name) # create logger @ info lvl
    log.setLevel(logging.INFO)
    sh = logging.StreamHandler()    # create streamhandler @ info lvl
    sh.setLevel(logging.INFO)
    sh.setFormatter(RelativeFormatter())    # add custom formatter
    log.addHandler(sh)
    return log


def load_modules(module_names):
    modules = []
    sys.path.append("./modules")    # add modules directory to search path
    for name in module_names:
        modules.append(importlib.import_module(name))
    return modules

def dump_hosts_to_file(i, hosts, filename):
    with open(filename, "w") as f:
        print(i, file=f)
        for host in hosts:
            print(host[0]+" "+host[1], file=f)



###
#
# The threads for:
#   loading the hosts
#   dispatching the hosts to the modules
#   saving the results
#
###

def Load(filename, resuming=False):
    global number_of_hosts, counter
    try:
        input_file = open(filename, "r")
        zero = int(input_file.readline()) if resuming else 0
        host_list = [line.strip().split() for line in input_file]
        input_file.close()
        log.info("Loaded hosts from file.")
    except IOError:
        log.error("Error: could not read in file!")
        os._exit(-1)

    # update the host number, reset counter
    number_of_hosts = len(host_list)
    counter = IntWrapper(zero, zero + number_of_hosts, conf.PRINT_FREQ)
    if resuming:
        log.info("Resuming suspended scan; %d/%d hosts scanned"
                %(zero, counter.total))

    file_loaded.set()

    for i in range(len(host_list)):
        if not SUSPEND:
            Qscan.put(host_list[i])
        else:
            number_of_hosts = i
            log.info("Dumping unscanned hosts to " + conf.SUSP_FILENAME)
            dump_hosts_to_file(zero + i, host_list[i:], conf.SUSP_FILENAME)
            log.info("Unscanned hosts dumped.\n"
                     "Please wait while the scans already in progress finish.")
            return



def Scan(modules):
    global counter
    while True:
        host = Qscan.get()
        Qscan.task_done()
        if not host:
            break
        host_results = []
        for m in modules:
            host_results.append( m.process(host) )
        Qsave.put(host_results)
        counter.inc()


def Save():

    # open the database and initialize if needed
    connection = sqlite3.connect(conf.DB_FILENAME, isolation_level=None)
    cursor = connection.cursor()
    for module in modules:
        module.init_db_tables(cursor)

    # wait until global vars are initialized
    file_loaded.wait()
    file_loaded.clear()

    cursor.execute("BEGIN TRANSACTION;")
    i=0
    while i < number_of_hosts:
        host_results = Qsave.get()
        for rec in host_results:
            rec.add_to_DB(cursor)
        i+=1

    connection.commit()
    connection.close()


###
#
# The entry point
#
###

if __name__=="__main__":

    parser = argparse.ArgumentParser()
    for option in options:
        parser.add_argument(*option[0], **option[1])
    conf = parser.parse_args()

    # do additional checks
    if conf.THREAD_NUM < 1:
        parser.error("thread number must be at least 1")
    elif conf.PRINT_FREQ < 1:
        parser.error("print frequency must be greater than zero")
    elif conf.MAX_Q_SIZE < 1:
        parser.error("queue size must be at least 1")

    # create and initialize logger, queues
    log = get_logger("main")
    Qscan = queue.Queue(conf.MAX_Q_SIZE)
    Qsave = queue.Queue(conf.MAX_Q_SIZE)

    # load modules
    log.info("Loading modules...")
    modules = load_modules(module_names)

    # start the worker threads
    worker_threads = []
    log.info("Starting the scanner threads...")
    for i in range(conf.THREAD_NUM):
        thread = threading.Thread(target=Scan, args=(modules,))
        thread.start()
        worker_threads.append(thread)

    # start the input thread
    log.info("Starting the loader thread...")
    if not conf.STATE_FILE:
        loader_thread = threading.Thread(target=Load, args=(sys.argv[1],))
    else:
        loader_thread = threading.Thread(target=Load, args=(conf.STATE_FILE, True))
    loader_thread.start()

    # start the output thread
    log.info("Starting the output thread...")
    saver_thread = threading.Thread(target=Save)
    saver_thread.start()

    while True:
        try:
            loader_thread.join()
            saver_thread.join()
        except KeyboardInterrupt:
            try:
                conf.REPEAT = False
                log.warning("Received KeyboardInterrupt, set REPEAT to off.\n"
                            "Send again within 3s to suspend execution")
                time.sleep(3)
            except KeyboardInterrupt:
                SUSPEND = True
                log.warning("Suspending...")
            continue

        # hope the user doesn't send KeyboardInterrupt *precisely* during
        #  the execution of these if-else branches
        # if he does, though, it'll quit the program instead of messing up
        #  the program state.

        if conf.REPEAT:
            loader_thread = threading.Thread(target=Load, args=(sys.argv[1],))
            saver_thread = threading.Thread(target=Save)
            loader_thread.start()
            saver_thread.start()
        else:
            for i in range(conf.THREAD_NUM):
                Qscan.put(None)
            for thread in worker_threads:
                thread.join()
            break


    log.info("Done.")
