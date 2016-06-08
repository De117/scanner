#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
import ssl
import socket
DETECT_CIPHERS = True
DEFAULT_TIMEOUT = 5.0

# creates a TCP socket wrapped in SSL
def make_ssocket(protocol, ciphers=ssl._DEFAULT_CIPHERS):
    return ssl.wrap_socket( socket.socket(),
                            ssl_version=protocol,
                            ciphers=ciphers)

# returns a list of ciphers supported by a host, on a given protocol version
def get_supported_ciphers(dest, protocol):
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



def process(host, stream):
    hostname, IP = host
    if (hostname=="?"):
        dest = (IP, 443)
    else:
        dest = (hostname, 443)
    # set default socket timeout
    socket.setdefaulttimeout(DEFAULT_TIMEOUT)
    # a dictionary to record the supported protocols
    supported = {}

    print("\nhost: "+hostname, file=stream)
    print("IPs: "+IP, file=stream)
    print("supports: ", file=stream)

    # detect supported protocol versions
    for proto_key in ssl._PROTOCOL_NAMES.keys():
        ssock = make_ssocket(proto_key)
        try:
            ssock.connect(dest)
            ssock.close()
            supported[proto_key] = True
        except OSError:
            supported[proto_key] = False

        # print out supported protocol versions
        if (supported[proto_key]):
            print("  "+ssl._PROTOCOL_NAMES[proto_key]+": YES", file=stream)
            # detect supported ciphers
            if (DETECT_CIPHERS):
                supported_ciphers = get_supported_ciphers(dest, proto_key)
                for cipher in supported_ciphers:
                    print("    "+cipher, file=stream)
        else:
            print("  "+ssl._PROTOCOL_NAMES[proto_key]+": NO", file=stream)
