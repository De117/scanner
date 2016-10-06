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
THREAD_NUM = 200
PRINT_FREQ = 10
MAX_Q_SIZE = 200
module_names = ["sslmodule"]
DB_NAME = "results.db"

Qin = queue.Queue(MAX_Q_SIZE)
Qout = queue.Queue(MAX_Q_SIZE)
number_of_hosts = None

class RelativeFormatter(logging.Formatter):
    """A custom formatter.
    
    Adds elapsed time (in seconds.milliseconds) in front of the message.
    """
    def format(self, record):
        ret = super().format(record)
        return "[%.4f] "%(record.relativeCreated/1000) + ret


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


def get_logger(name):
    """Creates and initializes the logger."""
    log = logging.getLogger(name) # create logger @ info lvl
    log.setLevel(logging.INFO)
    sh = logging.StreamHandler()    # create streamhandler @ info lvl
    sh.setLevel(logging.INFO)
    sh.setFormatter(RelativeFormatter())    # add custom formatter
    log.addHandler(sh)
    return log

def count_lines(filename):
    """Returns the number of lines in the specified file."""
    try:
        f = open(filename)
        return sum(1 for line in f)
    except IOError:
        log.error("Error: could not read in file!")
        os._exit(-1)

###
#
# The threads for:
#   loading the hosts
#   dispatching the hosts to the modules
#   saving the results
#
###

def Load(filename):
    global number_of_hosts
    try:
        input_file = open(filename, "r")
        # count the host number before loading
        number_of_hosts = sum(1 for line in input_file)
        input_file.seek(0)

        while True:
            host = input_file.readline().strip().split()
            if not host:
                break
            Qin.put(host)
        input_file.close()

        # when done, signal the end
        for i in range(THREAD_NUM):
            Qin.put(None)
        log.info("Finished loading hosts.")
    except IOError:
        log.error("Error: could not read in file!")
        os._exit(-1)


def Scan(modules, counter):
    while True:
        host = Qin.get()
        Qin.task_done()
        if not host:
            break
        host_results = []
        for m in modules:
            host_results.append( m.process(host) )
        Qout.put(host_results)
        counter.inc()


def Save():
    global number_of_hosts

    # open the database and initialize if needed
    connection = sqlite3.connect(DB_NAME, isolation_level=None)
    cursor = connection.cursor()
    for module in modules:
        module.init_db_tables(cursor)

    cursor.execute("BEGIN TRANSACTION;")
    for i in range(number_of_hosts):
        host_results = Qout.get()
        for rec in host_results:
            rec.add_to_DB(cursor)
    connection.commit()


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
    log = get_logger("main")

    # load modules
    log.info("Loading modules...")
    sys.path.append("./modules")    # add modules directory to search path
    modules = []
    for name in module_names:
        modules.append(importlib.import_module(name))

    number_of_hosts = count_lines(sys.argv[1])

    # start the input thread
    log.info("Starting the loader thread...")
    loader_thread = threading.Thread(target=Load, args=(sys.argv[1],))
    loader_thread.start()

    # start the output thread
    log.info("Starting the output thread...")
    saver_thread = threading.Thread(target=Save)
    saver_thread.start()

    # start the worker threads
    worker_threads = []
    counter = IntWrapper(0, number_of_hosts)
    log.info("Starting the scan...")
    for i in range(THREAD_NUM):
        thread = threading.Thread(target=Scan, args=(modules, counter))
        thread.start()
        worker_threads.append(thread)


    # collect the threads
    for thread in worker_threads:
        thread.join()
    loader_thread.join()
    saver_thread.join()


    log.info("Done.")
