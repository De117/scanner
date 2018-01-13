Starting with RFC 6066 extensions:

0. Server name indication (`server_name`, SNI)
--------------------------------------------
Indicates the server domain name; this enables the server to serve the right
certificate if multiple domains are hosted on the same IP.

Often a prerequisite for establishing a TLS connection at all.


1. Maximum fragment length negotiation (`max_frag_length`)
----------------------------------------------------------
Requests a lower max. fragment length at the Record layer.
Default one is 2^14, this one allows for 2^9, 2^10, 2^11, and 2^12 as well.

As of 2018-01-06, not widely supported.
OpenSSL added it in version 1.1.1, which is still in development;
 see [this Github issue][1] for more details.
LibreSSL still hasn't added it: see [this issue][2].
WolfSSL seems to have it, according to [their website][3].
As for the extension itself, [this thread][4] might be of interest.

[1]: https://github.com/openssl/openssl/pull/1008
[2]: https://github.com/libressl-portable/portable/issues/214
[3]: https://www.wolfssl.com/products/wolfssl/
[4]: https://www.ietf.org/mail-archive/web/tls/current/msg22058.html

So far, not testing for it.


2. Client certificate URL
-------------------------
Negotiates the use of a "CertificateURL" handshake message instead of "Certificate".
Used by resource-constrained clients. Client requests such use, and server MAY
indicate that they'll accept, by including the extension in ServerHello.

Is not implemented in OpenSSL (see [here][5]; a quick grep through source code
doesn't find CertificateURLs implemented at all.)
Additionally, [this 2016 book][6] suggests that it should by no means be
activated by default, so I don't expect anyone to be using it any time soon.

[5]: https://stackoverflow.com/questions/39613780/openssl-support-for-client-certificate-urls
[6]: https://books.google.nl/books?id=jm6uDgAAQBAJ&pg=PA120&lpg=PA120&dq=openssl+certificateURL&source=bl&ots=XJLuj3ktTK&sig=MWSV3QDVhoKjMx0I9Gm22klFc24&hl=en&sa=X&ved=0ahUKEwiovdauvMTYAhVLmbQKHcRbAAgQ6AEIVzAG#v=onepage&q=openssl%20certificateURL


3. Trusted CA indication (`trusted_ca_keys`)
--------------------------------------------
Lets a client indicate which CA keys it has. (Again, for resource-limited clients.)
Grepping through OpenSSL source code shows it's not implemented.
(Quick search doesn't find it implemented anywhere else, either.)

Not testing for it.


4. Truncated HMAC
-----------------
Negotiaties the use of just 80 bits of HMAC (instead of the whole HMAC).
Server agrees by including the extension in the server hello.


5. Certificate status request (`status_request`, a.k.a. OCSP stapling)
----------------------------------------------------------------------
Requests the server to attach an OCSP response in a "CertificateStatus"
handshake message, immediately after the "Certificate" message.

Once the server receives the extension in the client hello, it replies with
the extension in the server hello -- but it doesn't have to proceed to then
actually send the "CertificateStatus" message, for some reason.

(One would expect that a positive reply in the server hello must mean that a
"CertificateStatus" must be incoming, but it is not so. Weird.)


Here end the RFC 6066 extensions.


6. User mapping (`user_mapping`, RFC 4681)
------------------------------------------
Negotiates the use of SupplementalData messages in the handshake.
Those are for hints to the upper layers, more specifically MUST be intended
to be used exclusively by the layers above TLS, according to RFC 4680.
(Currently used only for UPN domain hints.)
Client sends list of supported UserMappingTypes, server responds with a subset.


7. (and 8.) TLS authorization extensions (`client_authz`, `server_authz`)
-------------------------------------------------------------------------
These are experimental, defined in RFC 5878. Skipping for now.


9. Certificate type (`cert_type`)
---------------------------------
Indicates the certificate type: X.509 or OpenPGP.
Used for requesting the use of OpenPGP certificates.
("OpenPGP certificate" meaning an OpenPGP key enabled for authentication.)
Client sends list of supported CertificateTypes, server chooses one.

Server MUST choose one or terminate with a fatal alert.
Client MUST NOT send this extension if it supports only X.509 certs.
Server MAY omit echoing this extension if it support only X.509 certs.

Given the last one, this one likely just tests for OpenPGP cert support.
(Which I'd assume is extremely rare.)

Not testing.


10. Supported groups (a.k.a. Elliptic curves, RFC 4492, additionally 7919)
--------------------------------------------------------------------------
Lets the server know which curve parameters the client supports.

The client proposing ECC cipher suites SHOULD use this.
The server MUST pick one of the client's offers, or not use ECC.
The client MUST NOT send this if it doesn't propose an ECC cipher suite.

However, it is NOT echoed in the server hello. We can just assume that
all servers supporting ECC will support this extension.


11. EC point formats
--------------------
Lets the other side know which point formats (compressed, uncompressed)
it can parse.
The three lines from above (SHOULD, MUST, and MUST NOT) also apply here.
Also, uncompressed(0) MUST be included, and is implied when this extension
is not sent (at least for the server hello).

The server doesn't necessarily send this one, but again, if it supports ECC
it should support this extension as well.


So, not explicitly testing for these two.
HOWEVER: it seems that `supported_groups` HAS TO be there in order to negotiate
         an EC cipher suite. (At least for some servers, it seems.)


12. SRP (RFC 5054)
------------------
Enables the use of the Secure Remote Password protocol for TLS authentication.
RFC is informational, and this is *definitely* not applicable to web-servers.


13. Signature algorithms (RFC 5246)
-----------------------------------
This one is part of the original TLS 1.2 specification.
Used to indicate which algorithm/hash pairs the client supports.
Servers MUST NOT send this extension.
TLS servers MUST support receiving this extension. (ignoring it in case of TLS <1.1)
If the client only support the default hash and signature algorithms,
it MAY omit sending this extension.

There's no way to easily discern what the server thinks about it.
I think it's safe to assume all servers support this.


14. Use SRTP (RFC 5764)
-----------------------
Not applicable to TLS. (Only DTLS.)


15. Heartbeat
-------------
Used to indicate whether a peer supports Heartbeats.
The Heartbeat protocol runs on top of the record layer.
They SHOULD NOT be sent during the handshake.

If the server either sends the extension, or can respond to a heartbeat,
it supports the extension.


16. Application layer protocol negotiation (ALPN, RFC 7301)
-----------------------------------------------------------
Negotiates the use of the application protocol, for situations when
multiple protocols run on the same port.
The client hello includes the list of supported application prototocols,
the server chooses one and returns it in the server hello.
(Strictly speaking, the server MAY include the response in the server hello.)


17. `status_request_v2` (OCSP multi-stapling, RFC 6961)
-------------------------------------------------------
Same as `status_request` (5), but can staple multiple OCSP replies.
It solves the problem of not being able to staple OCSP replies for the whole
certificate chain.


18. Signed certificate timestamp (certificate transparency, RFC 6962)
---------------------------------------------------------------------
Google's work. Experimental.
Requests the server to send an SCT in the server hello extension,
if I'm understanding the RFC correctly.


19. (20.) Client (Server) certificate type (RFC 7250)
-----------------------------------------------------
Indicates the certificate types that the client is able to provide (process)
to the server. Meant to signal support for using raw public keys.
I don't think this is applicable to public web-servers. Not testing for it.



21. Padding (RFC 7685)
----------------------
Adds padding to client hello, nothing more. Server MUST NOT echo the extension.


22. Encrypt-then-MAC (RFC 7366)
-------------------------------
Negotiates the use of encrypt-then-MAC (instead of default MAC-then-encrypt).
Client asks by including empty extension in hello, server confirms by echoing it.


23. Extended master secret (RFC 7627)
-------------------------------------
Negotiaties the use of a different derivation for the master secret.
Client asks by including empty extension in hello, server confirms by echoing it.


24. Token binding
-----------------
TEMPORARY, so not testing for it.


25. Cached info (RFC 7924)
--------------------------
Lets the server know which certificates/OCSP replies the client has cached,
so the server can skip sending them if they haven't changed.
The client sends a list of (type,hash) pairs; the server replies with a list
of types that client "guessed". More precisely: if the client has a stale copy
of a certain type, that type MUST NOT be included in the server's reply.

It doesn't seem clear whether the server will send an empty extension if the
client has only stale copies. (The client's extension MUST contain at least
one (type,hash) pair.) If it does not, that would complicate detection.

Also, OpenSSL doesn't have it *anywhere* in its source, not even constants.
Not testing for it.


35. SessionTicket TLS (RFC 4507)
--------------------------------
Signals support for session tickets.
Unlike session IDs, which require the server to remember sessions, session
tickets do the same thing statelessly: the ticket contains all the state the
server needs to continue the session.
(The server replies with an empty extension in the server hello, iff it will
issue a new session ticket.)


65281. Renegotiation info (RFC 5746)
------------------------------------
Asks for secure renegotiation. (Renegotiation == new handshake and parameters.)
Client asks by including empty extension in hello, server confirms by echoing it.
