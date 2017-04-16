#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
import ssl
import socket
import time
import datetime
import threading
import asn1crypto.x509
import requests
DETECT_CIPHERS = True
DEFAULT_TIMEOUT = 5.0
TABLE_NAME = "scan_results"


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


def get_certificate(dest):
    """Returns a DER-encoded certificate (as a bytes object).

    Arguments:
            dest -- the (IP, port) to connect to
    """
    try:
        ssock = make_ssocket(ssl.PROTOCOL_SSLv23)  # connects to SSLv3+
        ssock.connect(dest)
        der_cert = ssock.getpeercert(binary_form=True)
        ssock.close()
        return der_cert
    except OSError:
        return None
    # c = asn1crypto.x509.Certificate.load(der_cert)


def get_HTTP_header_fields(url, fieldnames):
    """Returns the contents of the specified HTTP response header fields.

    Arguments:
        url -- the website to check (in the form '[xyz://]www.example.com/')
        fieldnames -- a list of header field names; can be a single string,
                      in which case it is treated like a list of length one

    Returns:
        field_contents -- a mapping (dict) from fieldnames to their values;
                          empty in case of error or if there are no headers
    """
    url = "https://" + url.split("//", maxsplit=1)[-1]
    if type(fieldnames) is str:
        fieldnames = [fieldnames]

    field_contents = {}

    try:
        resp = requests.head(url, allow_redirects=True)
    except requests.RequestException as e:
        return {}

    return {k:v for (k,v) in resp.headers.items() if k in fieldnames}


class Record:
    """A class for storing the results of a single scan."""
    def __init__(self, host):
        self.hostname, self.IP = host
        self.protocols = []
        self.cipher_suites = []
        self.timestamp = int(time.time())
        self.certificate = None

    def add_protocol(self, protocol):
        if protocol not in self.protocols:
            self.protocols.append( protocol )

    def add_cipher_suite(self, csuite):
        if csuite not in self.cipher_suites:
            self.cipher_suites.append( csuite )

    def add_to_DB(self, db_cursor):
        cmd = "INSERT INTO {} VALUES (?,?,?,?,?,?);".format(TABLE_NAME)

        protos_string = "_$_".join(self.protocols)
        csuite_string = "_$_".join(sorted(self.cipher_suites))
        if not protos_string: protos_string = None
        if not csuite_string: csuite_string = None

        db_cursor.execute(cmd, (self.hostname, self.IP, self.timestamp,
                            protos_string, csuite_string, self.certificate))

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
    db_cursor.execute("CREATE TABLE IF NOT EXISTS scan_results(\n"
                      "    hostname TEXT,\n"
                      "    ip TEXT,\n"
                      "    timestamp INTEGER,\n"
                      "    protocols TEXT,\n"
                      "    ciphersuites TEXT,\n"
                      "    certificate BLOB,\n"
                      "    PRIMARY KEY (hostname, timestamp));")


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
            record.add_protocol(ssl._PROTOCOL_NAMES[proto_key])
            # #protocol = ProtocolSuites(ssl._PROTOCOL_NAMES[proto_key])
            # detect supported ciphers
            if (DETECT_CIPHERS):
                supported_ciphers = get_supported_ciphers(dest, proto_key)
                for cipher in supported_ciphers:
                    record.add_cipher_suite(cipher)

    # record the certificate
    record.certificate = get_certificate(dest)

    # record certain response header fields
    fields = get_HTTP_header_fields(hostname,
                                    ["Server",
                                     "Strict-Transport-Security",
                                     "Public-Key-Pins",
                                     "Public-Key-Pins-Report-Only"])
    record.HTTP_header_fields = fields;

    return record


class SSLTester(threading.Thread):

    def __init__(self, target_feed, results_feed):
        threading.Thread.__init__(self)
        self.target_feed = target_feed
        self.results_feed = results_feed

    def run(self):
        for target in self.target_feed:
            res = self._scan(target)
            self.results_feed.put(res)

    def _scan(self, target):
        return process(target)
