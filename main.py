#!/usr/bin/python3
# -*- coding: utf-8 -*-

import threading
import time
import sys
import os
import logging
import sqlite3
import argparse
import json
from options import options
from SSLTester import SSLTester, init_db_tables as init_db_tables


class RelativeFormatter(logging.Formatter):
    """A custom formatter.
    Adds elapsed time (in seconds.milliseconds) in front of the message.
    """
    def format(self, record):
        ret = super().format(record)
        return "[%.4f] "%(record.relativeCreated/1000) + ret


def get_logger(name):
    """Create and initialize the logger."""
    log = logging.getLogger(name) # create logger @ info lvl
    log.setLevel(logging.INFO)
    sh = logging.StreamHandler()    # create streamhandler @ info lvl
    sh.setLevel(logging.INFO)
    sh.setFormatter(RelativeFormatter())    # add custom formatter
    log.addHandler(sh)
    return log


# --------------------
#  queue-like classes
# --------------------

class Feeder:
    """An iterable queue-like class for feeding/providing the hosts one by one."""

    def __init__(self, host_list):
        self.host_list = host_list
        self.index = 0
        self.lock = threading.RLock()

    def __iter__(self):
        return self

    def __next__(self):
        with self.lock:
            if self.index >= len(self.host_list):
                raise StopIteration

            self.index += 1
            return self.host_list[self.index-1]

    def stop(self):
        """Stop the feeder from producing any more hosts.
           Returns the number of hosts already produced."""
        with self.lock:
            _index = self.index
            self.index = len(self.host_list)
            return _index

    def reset(self, index=0):
        """Reset the feeder to the position given by `index`."""
        with self.lock:
            self.index = index


class Receiver:
    """A container for receiving the scan results one by one."""

    def __init__(self):
        self.results = []
        self.lock = threading.RLock()
        self.flushed_until = 0          # prevents storing a value twice

    def put(self, item):
        """Store the given item in the container."""
        with self.lock:
            self.results.append( item )
            num = len(self.results)

            if num % conf.PRINT_FREQ==0:
                log.info("\tScanned {} hosts".format(num))

    def flush_to_db(self):
        """Flush the new scan results to the database."""
        # open the database and initialize if needed
        connection = sqlite3.connect(conf.DB_FILENAME, isolation_level=None)
        cursor     = connection.cursor()
        init_db_tables(cursor)
        cursor.execute("BEGIN TRANSACTION;")

        with self.lock:
            for rec in self.results[self.flushed_until:]:
                rec.add_to_DB(cursor)
            flushed_until = len(self.results)

        connection.commit();
        connection.close()

    def clear(self):
        """Clear (delete) all stored items."""
        with self.lock:
            self.results = []
            self.flushed_until = 0

    def suspend(self):
        """Flush to DB and return the number of hosts scanned so far."""
        with self.lock:
            self.flush_to_db()
            hosts_scanned = len(self.results)
            return hosts_scanned


# -------------------------
#  state-related functions
# -------------------------

def load_host_list(filename):
    """Load the host list from disk, and die in case of failure."""
    try:
        input_file = open(filename, "r")
        host_list = [line.strip().split() for line in input_file]
        input_file.close()
        log.info("Loaded hosts from file.")
    except IOError:
        log.error("Error: could not read in file!")
        os._exit(-1)

    return host_list


def suspend_state(feeder, receiver):
    """Stop everything, dump unscanned hosts to disk, and exit.
       This function never returns.
    """
    hosts_issued = feeder.stop()
    hosts_scanned = receiver.suspend()

    log.info("Stopping everything, dumping state to disk...")
    to_dump = feeder.host_list[hosts_scanned:]

    with open(conf.SUSP_FILENAME, "w") as f:
        json.dump([hosts_scanned, to_dump], f)

    log.info("State dumped. Exiting.")
    os._exit(-1)


def load_state():
    """Load state from disk.
    Returns a Feeder with the remaining hosts, a new Receiver,
    and the number of hosts that were scanned during the last run.
    """
    with open(conf.STATE_FILE) as f:
        hosts_scanned, host_list = json.load(f)

    feeder = Feeder(host_list)
    receiver = Receiver()

    return feeder, receiver, hosts_scanned



############################################################



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

    log = get_logger("main")


    if conf.STATE_FILE:
        target_feed, results_feed, hosts_scanned = load_state()
        log.info("Resuming scan; {} hosts scanned last time, {} remaining"
                .format(hosts_scanned, len(target_feed.host_list)))
    else:
        host_list = load_host_list(sys.argv[1])     # load host list
        target_feed = Feeder(host_list)             # input queue
        results_feed = Receiver()                   # output queue
        log.info("Starting scan; {} hosts remaining".format(len(host_list)))


    while True:

        # start the worker threads
        threads = []
        log.info("Starting the scanner threads...")
        for i in range(conf.THREAD_NUM):
            thread = SSLTester(target_feed, results_feed)
            thread.start()
            threads.append(thread)
        log.info("Started all threads.\nPress Ctrl+C to set REPEAT to off")

        # wait for them to finish (and watch for Ctrl+C)
        while True:
            try:
                for thread in threads:
                    thread.join()
                log.info("Joined all threads.")
                break

            except KeyboardInterrupt:
                # handle suspension
                try:
                    conf.REPEAT = False
                    log.warning(
                        "Received KeyboardInterrupt, set REPEAT to off.\n"
                        "Send again within 3s to suspend execution.")
                    time.sleep(3)
                except KeyboardInterrupt:
                    log.warning("Suspending state...")
                    suspend_state(target_feed, results_feed)
                    # `suspend_state` will not return.


        # store results in the DB, clear the queues/buffers
        results_feed.flush_to_db()
        results_feed.clear()
        target_feed.reset()

        if not conf.REPEAT:
            break

        # load everything anew
        host_list = load_host_list(sys.argv[1])     # load host list
        target_feed = Feeder(host_list)             # input queue
        results_feed = Receiver()                   # output queue
        log.info("\nRepeating scan; {} hosts remaining".format(len(host_list)))

    log.info("Done.")
