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
REPEAT = True

Qscan = queue.Queue(MAX_Q_SIZE)
Qsave = queue.Queue(MAX_Q_SIZE)
number_of_hosts = None

file_loaded = threading.Event()
saving_done = threading.Event()

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

    def single_load(filename):
        try:
            input_file = open(filename, "r")
            host_list = [line.strip().split() for line in input_file]
            input_file.close()
            log.info("Finished loading hosts.")
        except IOError:
            log.error("Error: could not read in file!")
            os._exit(-1)

        # update the host number, reset counter
        global number_of_hosts, counter
        number_of_hosts = len(host_list)
        counter = IntWrapper(0, number_of_hosts, PRINT_FREQ)
        file_loaded.set()

        for host in host_list:
            Qscan.put(host)

    while True:
        single_load(filename)
        # wait for this batch to finish
        saving_done.wait()
        saving_done.clear()
        if not REPEAT:
            break

    # when done, signal the end
    for i in range(THREAD_NUM):
        Qscan.put(None)


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

    def single_save():
        # open the database and initialize if needed
        connection = sqlite3.connect(DB_NAME, isolation_level=None)
        cursor = connection.cursor()
        for module in modules:
            module.init_db_tables(cursor)

        # wait until global vars are initialized
        file_loaded.wait()
        file_loaded.clear()

        cursor.execute("BEGIN TRANSACTION;")
        for i in range(number_of_hosts):
            host_results = Qsave.get()
            for rec in host_results:
                rec.add_to_DB(cursor)

        connection.commit()
        connection.close()
        saving_done.set()

    single_save()
    while REPEAT:
        single_save()


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
    modules = load_modules(module_names)

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
    log.info("Starting the scan...")
    for i in range(THREAD_NUM):
        thread = threading.Thread(target=Scan, args=(modules,))
        thread.start()
        worker_threads.append(thread)


    while True:
        try:
            # collect the remaining threads
            loader_thread.join()
            saver_thread.join()
            for thread in worker_threads:
                thread.join()
            break
        except KeyboardInterrupt:
            log.info("Received KeyboardInterrupt, setting REPEAT to False...")
            REPEAT = False
            #os._exit(-1)


    log.info("Done.")
