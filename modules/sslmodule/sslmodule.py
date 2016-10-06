#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
import ssl
import socket
import time
import datetime
DETECT_CIPHERS = True
DEFAULT_TIMEOUT = 5.0


def make_ssocket(protocol, ciphers=ssl._DEFAULT_CIPHERS):
    """Creates a TCP socket wrapped in SSL."""
    return ssl.wrap_socket( socket.socket(),
                            ssl_version=protocol,
                            ciphers=ciphers)

def get_supported_ciphers(dest, protocol):
    """Returns a list of ciphers supported by a host.

    Arguments:
        dest -- the (IP, port) to connect to
        protocol -- the SSL/TLS version to test; it is also
                     the index into the ssl._PROTOCOL_NAMES array

    The returned list contains cipher names.
    """
    chosen_ciphers = []
    # start by enabling all ciphers
    cipher_string = "ALL:aNULL:eNULL"
    while True:
        try:
            ssock = make_ssocket(protocol, cipher_string)
            ssock.connect(dest)
            # the connection will be made with the highest-priority cipher
            chosen_ciphers.append( ssock.cipher()[0] )
            ssock.close()
            # having detected the cipher, disable it
            cipher_string += ":!"+chosen_ciphers[-1]
        except OSError:
            # if no connection can be made with the remaining ciphers,
            #  it means we've enumerated all the supported ones
            break
    return chosen_ciphers


class ProtocolSuites:
    """A class for storing the name and the supported cipher suites 
        of a single protocol."""
    def __init__(self, protocol_name):
        self.name = protocol_name
        self.cipher_suites = []

    def add_cipher_suite(self, suite):
        if suite not in self.cipher_suites:
            self.cipher_suites.append( suite )

    def __eq__(self, other):
        return self.name == other.name \
                and self.cipher_suites == other.cipher_suites

    def __bool__(self):
        if not self.name:
            return False
        return bool(self.cipher_suites)


class Record:
    """A class for storing the results of a single scan."""
    def __init__(self, host):
        self.hostname, self.IP = host
        self.protocols = []
        self.timestamp = int(time.time())

    def add_protocol(self, protocol):
        if protocol not in self.protocols:
            self.protocols.append( protocol )

    def add_to_DB(self, db_cursor):
        cmd = "INSERT INTO sslmodule VALUES (?,?,?,?);"
        for protocol in self.protocols:
            for csuite in protocol.cipher_suites:
                db_cursor.execute(cmd,
                    (self.timestamp, self.IP, protocol.name, csuite))
        

    def __str__(self):
        s = "host: " + self.hostname + "\n"
        s += "IP: " + self.IP + "\n"
        s += "timestamp: " + datetime.datetime \
                                     .fromtimestamp(self.timestamp) \
                                     .isoformat(" ") + "\n"
        s += "supports:\n"
        for proto in self.protocols:
            s += "  "+proto.name+"\n"
            for cipher in proto.cipher_suites:
                s += "    "+cipher+"\n"

        return s

def init_db_tables(db_cursor):
    """Create the necessary database tables, if they do not already exist."""
    db_cursor.execute("CREATE TABLE IF NOT EXISTS sslmodule(\n"+\
                      "    ip TEXT,\n"+\
                      "    timestamp INTEGER,\n"+\
                      "    hostname TEXT,\n"+\
                      "    cipher_suite TEXT);")


def process(host):
    hostname, IP = host
    if (hostname=="?"):
        dest = (IP, 443)
    else:
        dest = (hostname, 443)
    # set default socket timeout
    socket.setdefaulttimeout(DEFAULT_TIMEOUT)
    # a dictionary to record the supported protocols
    supported = {}

    record = Record(host)

    # detect supported protocol versions
    for proto_key in ssl._PROTOCOL_NAMES.keys():
        ssock = make_ssocket(proto_key)
        try:
            ssock.connect(dest)
            ssock.close()
            supported[proto_key] = True
        except OSError:
            supported[proto_key] = False

        if (supported[proto_key]):
            protocol = ProtocolSuites(ssl._PROTOCOL_NAMES[proto_key])
            # detect supported ciphers
            if (DETECT_CIPHERS):
                supported_ciphers = get_supported_ciphers(dest, proto_key)
                for cipher in supported_ciphers:
                    protocol.add_cipher_suite(cipher)
                record.add_protocol(protocol)
    return record