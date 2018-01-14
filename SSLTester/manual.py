from enum import Enum
import os
import sys
import time
import socket
import asn1crypto.x509

class ByteEnum(Enum):
    """A standard enum.Enum, with just a few extra classmethods for convenience"""
    @classmethod
    def find(cls, x : bytes):
        for _x in cls:
            if x == _x.value:
                return _x

    @classmethod
    def as_bytes(cls, bytes_iterable):
        return b"".join(e.value for e in bytes_iterable)

    @classmethod
    def from_bytes(cls, bytestream):
        alignment = len([_.value for _ in cls][0])
        if len(bytestream) % alignment:
            raise ValueError("Not an integral number of ByteEnums")
        splat = [bytestream[i:i+2] for i in range(0,len(bytestream),alignment)]
        return [[e for e in cls if e.value == b][0] for b in splat]


class RecordType(ByteEnum): # ContentType in RFC2246
    """The type of the record (at the record protocol layer)"""
    change_cipher_spec = b'\x14'    # 20
    alert              = b'\x15'    # 21
    handshake          = b'\x16'    # 22
    application_data   = b'\x17'    # 23
    heartbeat          = b'\x18'    # 24


class SSLVersion(ByteEnum):
    SSLv2   = b'\x02\x00'
    SSLv3   = b'\x03\x00'
    TLSv1   = b'\x03\x01'
    TLSv1_1 = b'\x03\x02'
    TLSv1_2 = b'\x03\x03'
    TLSv1_3 = b'\x03\x04'

    def __lt__(a, b): return a.value < b.value
    def __le__(a, b): return a.value <= b.value


class HandshakeType(ByteEnum):
    """The type of the handshake message (over the record protocol layer)"""
    hello_request        = b'\x00'
    client_hello         = b'\x01'
    server_hello         = b'\x02'
    hello_verify_request = b'\x03'
    NewSessionTicket     = b'\x04'
                                     # 5-10 unassigned
    certificate          = b'\x0B'
    server_key_exchange  = b'\x0C'
    certificate_request  = b'\x0D'
    server_hello_done    = b'\x0E'
    certificate_verify   = b'\x0F'
    client_key_exchange  = b'\x10'
                                     # 17-19 unassigned
    finished             = b'\x14'
    certificate_url      = b'\x15'
    certificate_status   = b'\x16'
    supplemental_data    = b'\x17'
                                     # 24-255 unassigned


class AlertType(ByteEnum):
    close_notify                = b'\x00'   # 0
    unexpected_message          = b'\x0a'   # 10
    bad_record_mac              = b'\x14'   # 20
    decryption_failed_RESERVED  = b'\x15'   # 21
    record_overflow             = b'\x16'   # 22
    decompression_failure       = b'\x1e'   # 30
    handshake_failure           = b'\x28'   # 40
    no_certificate_RESERVED     = b'\x29'   # 41
    bad_certificate             = b'\x2a'   # 42
    unsupported_certificate     = b'\x2b'   # 43
    certificate_revoked         = b'\x2c'   # 44
    certificate_expired         = b'\x2d'   # 45
    certificate_unknown         = b'\x2e'   # 46
    illegal_parameter           = b'\x2f'   # 47
    unknown_ca                  = b'\x30'   # 48
    access_denied               = b'\x31'   # 49
    decode_error                = b'\x32'   # 50
    decrypt_error               = b'\x33'   # 51
    export_restriction_RESERVED = b'\x3c'   # 60
    protocol_version            = b'\x46'   # 70
    insufficient_security       = b'\x47'   # 71
    internal_error              = b'\x50'   # 80
    user_canceled               = b'\x5a'   # 90
    no_renegotiation            = b'\x64'   # 100
    unsupported_extension       = b'\x6e'   # 110


def decode_alert(alert):
    """Decode alert message. For interactive use."""
    alert = alert[5:]
    level = "Fatal: "
    if alert[0] == b'\x01':
        level = "Warning: "
    return level + [atype.name for atype in AlertType if atype.value == alert[1:2]][0]


class NamedCurve(ByteEnum):
    """Elliptic curves used in TLS."""
    # 0, unassigned
    sect163k1 = b"\x00\x01"
    sect163r1 = b"\x00\x02"
    sect163r2 = b"\x00\x03"
    sect193r1 = b"\x00\x04"
    sect193r2 = b"\x00\x05"
    sect233k1 = b"\x00\x06"
    sect233r1 = b"\x00\x07"
    sect239k1 = b"\x00\x08"
    sect283k1 = b"\x00\x09"
    sect283r1 = b"\x00\x0a"
    sect409k1 = b"\x00\x0b"
    sect409r1 = b"\x00\x0c"
    sect571k1 = b"\x00\x0d"
    sect571r1 = b"\x00\x0e"
    secp160k1 = b"\x00\x0f"
    secp160r1 = b"\x00\x10"
    secp160r2 = b"\x00\x11"
    secp192k1 = b"\x00\x12"
    secp192r1 = b"\x00\x13"
    secp224k1 = b"\x00\x14"
    secp224r1 = b"\x00\x15"
    secp256k1 = b"\x00\x16"
    secp256r1 = b"\x00\x17"
    secp384r1 = b"\x00\x18"
    secp521r1 = b"\x00\x19"
    brainpoolP256r1 = b"\x00\x1a"
    brainpoolP384r1 = b"\x00\x1b"
    brainpoolP512r1 = b"\x00\x1c"
    x25519    = b"\x00\x1d"
    x448      = b"\x00\x1e"
    # 31-255 unassigned
    ffdhe2048 = b"\x01\x00"
    ffdhe3072 = b"\x01\x01"
    ffdhe4096 = b"\x01\x02"
    ffdhe6144 = b"\x01\x03"
    ffdhe8192 = b"\x01\x04"
    # 261-507 unassigned
    # 508-511 reserved for private use
    # 512-65023 unassigned
    # 65024-65279 reserved for private use
    # 65280 unassigned

    # These require explicit parameters to be provided beside them
    #arbitrary_explicit_prime_curves = b"\xff\x01"
    #arbitrary_explicit_char2_curves = b"\xff\x02"

    # 65283-65535 unassigned


class ExtensionType(ByteEnum):
    """TLS extension types.
    For more details on TLS extensions, see RFC 5246, section 7.4.1.4.
    """
    server_name                            = b"\x00\x00"
    max_fragment_length                    = b"\x00\x01"
    client_certificate_url                 = b"\x00\x02"
    trusted_ca_keys                        = b"\x00\x03"
    truncated_hmac                         = b"\x00\x04"
    status_request                         = b"\x00\x05"
    user_mapping                           = b"\x00\x06"
    client_authz                           = b"\x00\x07"
    server_authz                           = b"\x00\x08"
    cert_type                              = b"\x00\x09"
    supported_groups                       = b"\x00\x0a"    # renamed from "elliptic_curves"
    ec_point_formats                       = b"\x00\x0b"
    srp                                    = b"\x00\x0c"
    signature_algorithms                   = b"\x00\x0d"
    use_strp                               = b"\x00\x0e"
    heartbeat                              = b"\x00\x0f"
    application_layer_protocol_negotiation = b"\x00\x10"
    status_request_v2                      = b"\x00\x11"
    signed_certificate_timestamp           = b"\x00\x12"
    client_certificate_type                = b"\x00\x13"
    server_certificate_type                = b"\x00\x14"
    padding                                = b"\x00\x15"
    encrypt_then_mac                       = b"\x00\x16"
    extended_master_secret                 = b"\x00\x17"
    token_binding                          = b"\x00\x18"    # TEMPORARY
    cached_info                            = b"\x00\x19"
                                                            # 26-34 unassigned
    session_ticket_TLS                     = b"\x00\x23"
                                                            # 36-65280 unassigned
    renegotiation_info                     = b"\xff\x01"
                                                            # 65282-65535 unassigned

    def __lt__(a, b): return a.value < b.value
    def __le__(a, b): return a.value <= b.value


class CipherSuite(ByteEnum):
    """List of all TLS ciphersuites,
    taken from `https://www.iana.org/assignments/tls-parameters/`"""
    TLS_NULL_WITH_NULL_NULL                       = b'\x00\x00' 
    TLS_RSA_WITH_NULL_MD5                         = b'\x00\x01' 
    TLS_RSA_WITH_NULL_SHA                         = b'\x00\x02' 
    TLS_RSA_EXPORT_WITH_RC4_40_MD5                = b'\x00\x03' 
    TLS_RSA_WITH_RC4_128_MD5                      = b'\x00\x04' 
    TLS_RSA_WITH_RC4_128_SHA                      = b'\x00\x05' 
    TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5            = b'\x00\x06' 
    TLS_RSA_WITH_IDEA_CBC_SHA                     = b'\x00\x07' 
    TLS_RSA_EXPORT_WITH_DES40_CBC_SHA             = b'\x00\x08' 
    TLS_RSA_WITH_DES_CBC_SHA                      = b'\x00\x09' 
    TLS_RSA_WITH_3DES_EDE_CBC_SHA                 = b'\x00\x0A' 
    TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA          = b'\x00\x0B' 
    TLS_DH_DSS_WITH_DES_CBC_SHA                   = b'\x00\x0C' 
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA              = b'\x00\x0D' 
    TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA          = b'\x00\x0E' 
    TLS_DH_RSA_WITH_DES_CBC_SHA                   = b'\x00\x0F' 
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA              = b'\x00\x10' 
    TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA         = b'\x00\x11' 
    TLS_DHE_DSS_WITH_DES_CBC_SHA                  = b'\x00\x12' 
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA             = b'\x00\x13' 
    TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA         = b'\x00\x14' 
    TLS_DHE_RSA_WITH_DES_CBC_SHA                  = b'\x00\x15' 
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA             = b'\x00\x16' 
    TLS_DH_anon_EXPORT_WITH_RC4_40_MD5            = b'\x00\x17' 
    TLS_DH_anon_WITH_RC4_128_MD5                  = b'\x00\x18' 
    TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA         = b'\x00\x19' 
    TLS_DH_anon_WITH_DES_CBC_SHA                  = b'\x00\x1A' 
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA             = b'\x00\x1B' 
    TLS_KRB5_WITH_DES_CBC_SHA                     = b'\x00\x1E' 
    TLS_KRB5_WITH_3DES_EDE_CBC_SHA                = b'\x00\x1F' 
    TLS_KRB5_WITH_RC4_128_SHA                     = b'\x00\x20' 
    TLS_KRB5_WITH_IDEA_CBC_SHA                    = b'\x00\x21' 
    TLS_KRB5_WITH_DES_CBC_MD5                     = b'\x00\x22' 
    TLS_KRB5_WITH_3DES_EDE_CBC_MD5                = b'\x00\x23' 
    TLS_KRB5_WITH_RC4_128_MD5                     = b'\x00\x24' 
    TLS_KRB5_WITH_IDEA_CBC_MD5                    = b'\x00\x25' 
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA           = b'\x00\x26' 
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA           = b'\x00\x27' 
    TLS_KRB5_EXPORT_WITH_RC4_40_SHA               = b'\x00\x28' 
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5           = b'\x00\x29' 
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5           = b'\x00\x2A' 
    TLS_KRB5_EXPORT_WITH_RC4_40_MD5               = b'\x00\x2B' 
    TLS_PSK_WITH_NULL_SHA                         = b'\x00\x2C' 
    TLS_DHE_PSK_WITH_NULL_SHA                     = b'\x00\x2D' 
    TLS_RSA_PSK_WITH_NULL_SHA                     = b'\x00\x2E' 
    TLS_RSA_WITH_AES_128_CBC_SHA                  = b'\x00\x2F' 
    TLS_DH_DSS_WITH_AES_128_CBC_SHA               = b'\x00\x30' 
    TLS_DH_RSA_WITH_AES_128_CBC_SHA               = b'\x00\x31' 
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA              = b'\x00\x32' 
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA              = b'\x00\x33' 
    TLS_DH_anon_WITH_AES_128_CBC_SHA              = b'\x00\x34' 
    TLS_RSA_WITH_AES_256_CBC_SHA                  = b'\x00\x35' 
    TLS_DH_DSS_WITH_AES_256_CBC_SHA               = b'\x00\x36' 
    TLS_DH_RSA_WITH_AES_256_CBC_SHA               = b'\x00\x37' 
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA              = b'\x00\x38' 
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA              = b'\x00\x39' 
    TLS_DH_anon_WITH_AES_256_CBC_SHA              = b'\x00\x3A' 
    TLS_RSA_WITH_NULL_SHA256                      = b'\x00\x3B' 
    TLS_RSA_WITH_AES_128_CBC_SHA256               = b'\x00\x3C' 
    TLS_RSA_WITH_AES_256_CBC_SHA256               = b'\x00\x3D' 
    TLS_DH_DSS_WITH_AES_128_CBC_SHA256            = b'\x00\x3E' 
    TLS_DH_RSA_WITH_AES_128_CBC_SHA256            = b'\x00\x3F' 
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256           = b'\x00\x40' 
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA             = b'\x00\x41' 
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA          = b'\x00\x42' 
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA          = b'\x00\x43' 
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA         = b'\x00\x44' 
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA         = b'\x00\x45' 
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA         = b'\x00\x46' 
    TLS_DH_DSS_WITH_AES_256_CBC_SHA256            = b'\x00\x68' 
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256            = b'\x00\x69' 
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256           = b'\x00\x6A' 
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256           = b'\x00\x6B' 
    TLS_DH_anon_WITH_AES_128_CBC_SHA256           = b'\x00\x6C' 
    TLS_DH_anon_WITH_AES_256_CBC_SHA256           = b'\x00\x6D' 
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA             = b'\x00\x84' 
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA          = b'\x00\x85' 
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA          = b'\x00\x86' 
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA         = b'\x00\x87' 
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA         = b'\x00\x88' 
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA         = b'\x00\x89' 
    TLS_PSK_WITH_RC4_128_SHA                      = b'\x00\x8A' 
    TLS_PSK_WITH_3DES_EDE_CBC_SHA                 = b'\x00\x8B' 
    TLS_PSK_WITH_AES_128_CBC_SHA                  = b'\x00\x8C' 
    TLS_PSK_WITH_AES_256_CBC_SHA                  = b'\x00\x8D' 
    TLS_DHE_PSK_WITH_RC4_128_SHA                  = b'\x00\x8E' 
    TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA             = b'\x00\x8F' 
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA              = b'\x00\x90' 
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA              = b'\x00\x91' 
    TLS_RSA_PSK_WITH_RC4_128_SHA                  = b'\x00\x92' 
    TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA             = b'\x00\x93' 
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA              = b'\x00\x94' 
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA              = b'\x00\x95' 
    TLS_RSA_WITH_SEED_CBC_SHA                     = b'\x00\x96' 
    TLS_DH_DSS_WITH_SEED_CBC_SHA                  = b'\x00\x97' 
    TLS_DH_RSA_WITH_SEED_CBC_SHA                  = b'\x00\x98' 
    TLS_DHE_DSS_WITH_SEED_CBC_SHA                 = b'\x00\x99' 
    TLS_DHE_RSA_WITH_SEED_CBC_SHA                 = b'\x00\x9A' 
    TLS_DH_anon_WITH_SEED_CBC_SHA                 = b'\x00\x9B' 
    TLS_RSA_WITH_AES_128_GCM_SHA256               = b'\x00\x9C' 
    TLS_RSA_WITH_AES_256_GCM_SHA384               = b'\x00\x9D' 
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256           = b'\x00\x9E' 
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384           = b'\x00\x9F' 
    TLS_DH_RSA_WITH_AES_128_GCM_SHA256            = b'\x00\xA0' 
    TLS_DH_RSA_WITH_AES_256_GCM_SHA384            = b'\x00\xA1' 
    TLS_DHE_DSS_WITH_AES_128_GCM_SHA256           = b'\x00\xA2' 
    TLS_DHE_DSS_WITH_AES_256_GCM_SHA384           = b'\x00\xA3' 
    TLS_DH_DSS_WITH_AES_128_GCM_SHA256            = b'\x00\xA4' 
    TLS_DH_DSS_WITH_AES_256_GCM_SHA384            = b'\x00\xA5' 
    TLS_DH_anon_WITH_AES_128_GCM_SHA256           = b'\x00\xA6' 
    TLS_DH_anon_WITH_AES_256_GCM_SHA384           = b'\x00\xA7' 
    TLS_PSK_WITH_AES_128_GCM_SHA256               = b'\x00\xA8' 
    TLS_PSK_WITH_AES_256_GCM_SHA384               = b'\x00\xA9' 
    TLS_DHE_PSK_WITH_AES_128_GCM_SHA256           = b'\x00\xAA' 
    TLS_DHE_PSK_WITH_AES_256_GCM_SHA384           = b'\x00\xAB' 
    TLS_RSA_PSK_WITH_AES_128_GCM_SHA256           = b'\x00\xAC' 
    TLS_RSA_PSK_WITH_AES_256_GCM_SHA384           = b'\x00\xAD' 
    TLS_PSK_WITH_AES_128_CBC_SHA256               = b'\x00\xAE' 
    TLS_PSK_WITH_AES_256_CBC_SHA384               = b'\x00\xAF' 
    TLS_PSK_WITH_NULL_SHA256                      = b'\x00\xB0' 
    TLS_PSK_WITH_NULL_SHA384                      = b'\x00\xB1' 
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA256           = b'\x00\xB2' 
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA384           = b'\x00\xB3' 
    TLS_DHE_PSK_WITH_NULL_SHA256                  = b'\x00\xB4' 
    TLS_DHE_PSK_WITH_NULL_SHA384                  = b'\x00\xB5' 
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA256           = b'\x00\xB6' 
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA384           = b'\x00\xB7' 
    TLS_RSA_PSK_WITH_NULL_SHA256                  = b'\x00\xB8' 
    TLS_RSA_PSK_WITH_NULL_SHA384                  = b'\x00\xB9' 
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256          = b'\x00\xBA' 
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256       = b'\x00\xBB' 
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256       = b'\x00\xBC' 
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256      = b'\x00\xBD' 
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256      = b'\x00\xBE' 
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256      = b'\x00\xBF' 
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256          = b'\x00\xC0' 
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256       = b'\x00\xC1' 
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256       = b'\x00\xC2' 
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256      = b'\x00\xC3' 
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256      = b'\x00\xC4' 
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256      = b'\x00\xC5' 
    # TLS_EMPTY_RENEGOTIATION_INFO_SCSV             = b'\x00\xFF' 
    # TLS_FALLBACK_SCSV                             = b'\x56\x00' 
    TLS_ECDH_ECDSA_WITH_NULL_SHA                  = b'\xC0\x01' 
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA               = b'\xC0\x02' 
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA          = b'\xC0\x03' 
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA           = b'\xC0\x04' 
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA           = b'\xC0\x05' 
    TLS_ECDHE_ECDSA_WITH_NULL_SHA                 = b'\xC0\x06' 
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA              = b'\xC0\x07' 
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA         = b'\xC0\x08' 
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA          = b'\xC0\x09' 
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA          = b'\xC0\x0A' 
    TLS_ECDH_RSA_WITH_NULL_SHA                    = b'\xC0\x0B' 
    TLS_ECDH_RSA_WITH_RC4_128_SHA                 = b'\xC0\x0C' 
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA            = b'\xC0\x0D' 
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA             = b'\xC0\x0E' 
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA             = b'\xC0\x0F' 
    TLS_ECDHE_RSA_WITH_NULL_SHA                   = b'\xC0\x10' 
    TLS_ECDHE_RSA_WITH_RC4_128_SHA                = b'\xC0\x11' 
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA           = b'\xC0\x12' 
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA            = b'\xC0\x13' 
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA            = b'\xC0\x14' 
    TLS_ECDH_anon_WITH_NULL_SHA                   = b'\xC0\x15' 
    TLS_ECDH_anon_WITH_RC4_128_SHA                = b'\xC0\x16' 
    TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA           = b'\xC0\x17' 
    TLS_ECDH_anon_WITH_AES_128_CBC_SHA            = b'\xC0\x18' 
    TLS_ECDH_anon_WITH_AES_256_CBC_SHA            = b'\xC0\x19' 
    TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA             = b'\xC0\x1A' 
    TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA         = b'\xC0\x1B' 
    TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA         = b'\xC0\x1C' 
    TLS_SRP_SHA_WITH_AES_128_CBC_SHA              = b'\xC0\x1D' 
    TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA          = b'\xC0\x1E' 
    TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA          = b'\xC0\x1F' 
    TLS_SRP_SHA_WITH_AES_256_CBC_SHA              = b'\xC0\x20' 
    TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA          = b'\xC0\x21' 
    TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA          = b'\xC0\x22' 
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256       = b'\xC0\x23' 
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384       = b'\xC0\x24' 
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256        = b'\xC0\x25' 
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384        = b'\xC0\x26' 
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256         = b'\xC0\x27' 
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384         = b'\xC0\x28' 
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256          = b'\xC0\x29' 
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384          = b'\xC0\x2A' 
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       = b'\xC0\x2B' 
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       = b'\xC0\x2C' 
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256        = b'\xC0\x2D' 
    TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384        = b'\xC0\x2E' 
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         = b'\xC0\x2F' 
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         = b'\xC0\x30' 
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256          = b'\xC0\x31' 
    TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384          = b'\xC0\x32' 
    TLS_ECDHE_PSK_WITH_RC4_128_SHA                = b'\xC0\x33' 
    TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA           = b'\xC0\x34' 
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA            = b'\xC0\x35' 
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA            = b'\xC0\x36' 
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256         = b'\xC0\x37' 
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384         = b'\xC0\x38' 
    TLS_ECDHE_PSK_WITH_NULL_SHA                   = b'\xC0\x39' 
    TLS_ECDHE_PSK_WITH_NULL_SHA256                = b'\xC0\x3A' 
    TLS_ECDHE_PSK_WITH_NULL_SHA384                = b'\xC0\x3B' 
    TLS_RSA_WITH_ARIA_128_CBC_SHA256              = b'\xC0\x3C' 
    TLS_RSA_WITH_ARIA_256_CBC_SHA384              = b'\xC0\x3D' 
    TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256           = b'\xC0\x3E' 
    TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384           = b'\xC0\x3F' 
    TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256           = b'\xC0\x40' 
    TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384           = b'\xC0\x41' 
    TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256          = b'\xC0\x42' 
    TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384          = b'\xC0\x43' 
    TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256          = b'\xC0\x44' 
    TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384          = b'\xC0\x45' 
    TLS_DH_anon_WITH_ARIA_128_CBC_SHA256          = b'\xC0\x46' 
    TLS_DH_anon_WITH_ARIA_256_CBC_SHA384          = b'\xC0\x47' 
    TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256      = b'\xC0\x48' 
    TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384      = b'\xC0\x49' 
    TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256       = b'\xC0\x4A' 
    TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384       = b'\xC0\x4B' 
    TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256        = b'\xC0\x4C' 
    TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384        = b'\xC0\x4D' 
    TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256         = b'\xC0\x4E' 
    TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384         = b'\xC0\x4F' 
    TLS_RSA_WITH_ARIA_128_GCM_SHA256              = b'\xC0\x50' 
    TLS_RSA_WITH_ARIA_256_GCM_SHA384              = b'\xC0\x51' 
    TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256          = b'\xC0\x52' 
    TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384          = b'\xC0\x53' 
    TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256           = b'\xC0\x54' 
    TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384           = b'\xC0\x55' 
    TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256          = b'\xC0\x56' 
    TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384          = b'\xC0\x57' 
    TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256           = b'\xC0\x58' 
    TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384           = b'\xC0\x59' 
    TLS_DH_anon_WITH_ARIA_128_GCM_SHA256          = b'\xC0\x5A' 
    TLS_DH_anon_WITH_ARIA_256_GCM_SHA384          = b'\xC0\x5B' 
    TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256      = b'\xC0\x5C' 
    TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384      = b'\xC0\x5D' 
    TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256       = b'\xC0\x5E' 
    TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384       = b'\xC0\x5F' 
    TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256        = b'\xC0\x60' 
    TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384        = b'\xC0\x61' 
    TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256         = b'\xC0\x62' 
    TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384         = b'\xC0\x63' 
    TLS_PSK_WITH_ARIA_128_CBC_SHA256              = b'\xC0\x64' 
    TLS_PSK_WITH_ARIA_256_CBC_SHA384              = b'\xC0\x65' 
    TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256          = b'\xC0\x66' 
    TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384          = b'\xC0\x67' 
    TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256          = b'\xC0\x68' 
    TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384          = b'\xC0\x69' 
    TLS_PSK_WITH_ARIA_128_GCM_SHA256              = b'\xC0\x6A' 
    TLS_PSK_WITH_ARIA_256_GCM_SHA384              = b'\xC0\x6B' 
    TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256          = b'\xC0\x6C' 
    TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384          = b'\xC0\x6D' 
    TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256          = b'\xC0\x6E' 
    TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384          = b'\xC0\x6F' 
    TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256        = b'\xC0\x70' 
    TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384        = b'\xC0\x71' 
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256  = b'\xC0\x72' 
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384  = b'\xC0\x73' 
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256   = b'\xC0\x74' 
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384   = b'\xC0\x75' 
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256    = b'\xC0\x76' 
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384    = b'\xC0\x77' 
    TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256     = b'\xC0\x78' 
    TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384     = b'\xC0\x79' 
    TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256          = b'\xC0\x7A' 
    TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384          = b'\xC0\x7B' 
    TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256      = b'\xC0\x7C' 
    TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384      = b'\xC0\x7D' 
    TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256       = b'\xC0\x7E' 
    TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384       = b'\xC0\x7F' 
    TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256      = b'\xC0\x80' 
    TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384      = b'\xC0\x81' 
    TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256       = b'\xC0\x82' 
    TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384       = b'\xC0\x83' 
    TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256      = b'\xC0\x84' 
    TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384      = b'\xC0\x85' 
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256  = b'\xC0\x86' 
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384  = b'\xC0\x87' 
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256   = b'\xC0\x88' 
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384   = b'\xC0\x89' 
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256    = b'\xC0\x8A' 
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384    = b'\xC0\x8B' 
    TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256     = b'\xC0\x8C' 
    TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384     = b'\xC0\x8D' 
    TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256          = b'\xC0\x8E' 
    TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384          = b'\xC0\x8F' 
    TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256      = b'\xC0\x90' 
    TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384      = b'\xC0\x91' 
    TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256      = b'\xC0\x92' 
    TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384      = b'\xC0\x93' 
    TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256          = b'\xC0\x94' 
    TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384          = b'\xC0\x95' 
    TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256      = b'\xC0\x96' 
    TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384      = b'\xC0\x97' 
    TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256      = b'\xC0\x98' 
    TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384      = b'\xC0\x99' 
    TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256    = b'\xC0\x9A' 
    TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384    = b'\xC0\x9B' 
    TLS_RSA_WITH_AES_128_CCM                      = b'\xC0\x9C' 
    TLS_RSA_WITH_AES_256_CCM                      = b'\xC0\x9D' 
    TLS_DHE_RSA_WITH_AES_128_CCM                  = b'\xC0\x9E' 
    TLS_DHE_RSA_WITH_AES_256_CCM                  = b'\xC0\x9F' 
    TLS_RSA_WITH_AES_128_CCM_8                    = b'\xC0\xA0' 
    TLS_RSA_WITH_AES_256_CCM_8                    = b'\xC0\xA1' 
    TLS_DHE_RSA_WITH_AES_128_CCM_8                = b'\xC0\xA2' 
    TLS_DHE_RSA_WITH_AES_256_CCM_8                = b'\xC0\xA3' 
    TLS_PSK_WITH_AES_128_CCM                      = b'\xC0\xA4' 
    TLS_PSK_WITH_AES_256_CCM                      = b'\xC0\xA5' 
    TLS_DHE_PSK_WITH_AES_128_CCM                  = b'\xC0\xA6' 
    TLS_DHE_PSK_WITH_AES_256_CCM                  = b'\xC0\xA7' 
    TLS_PSK_WITH_AES_128_CCM_8                    = b'\xC0\xA8' 
    TLS_PSK_WITH_AES_256_CCM_8                    = b'\xC0\xA9' 
    TLS_PSK_DHE_WITH_AES_128_CCM_8                = b'\xC0\xAA' 
    TLS_PSK_DHE_WITH_AES_256_CCM_8                = b'\xC0\xAB' 
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM              = b'\xC0\xAC' 
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM              = b'\xC0\xAD' 
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8            = b'\xC0\xAE' 
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8            = b'\xC0\xAF' 
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = b'\xCC\xA8' 
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = b'\xCC\xA9' 
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256     = b'\xCC\xAA' 
    TLS_PSK_WITH_CHACHA20_POLY1305_SHA256         = b'\xCC\xAB' 
    TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256   = b'\xCC\xAC' 
    TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256     = b'\xCC\xAD' 
    TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256     = b'\xCC\xAE' 

    def __lt__(a, b): return a.value < b.value
    def __le__(a, b): return a.value <= b.value


# Divide ciphersuites into disjoint sets, depending on how frequent they are.
# We can then check the rarely used ones as a block, and fall back to checking
#  individual ciphersuites in case some of them are actually supported.

weak_csuites = [cs for cs in CipherSuite if ("anon" in cs.name or
                                             "NULL" in cs.name or
                                             "EXPORT" in cs.name)]

rare_csuites = [cs for cs in CipherSuite if ("_DH_" in cs.name or
                                             "_PSK_" in cs.name or
                                             "_SRP_" in cs.name or
                                             "_KRB5_" in cs.name or
                                             "_ARIA_" in cs.name) and
                                             cs not in weak_csuites]

frequent_csuites = [cs for cs in CipherSuite if (cs not in weak_csuites and
                                                 cs not in rare_csuites)]

def lenprefix(data, nbytes=2):
    """Prefix `data` with its length, in `nbytes` big-endian bytes.
    If `data` is a string, it is first converted to bytes as UTF-8.
    """
    assert type(data) in (str, bytes)
    if type(data) is str:
        data = bytes(data, "utf8")
    return len(data).to_bytes(nbytes, "big") + data


def crext_SNI(sni_url):
    """Create a SNI extension, prefixed with its two-byte length"""
    # start with single server hostname
    #  (0x00 is the server name type; as of 2017, there's only one)
    hostname = (b'\x00' + lenprefix(sni_url))

    # wrap all hostnames into server name list
    snlist = lenprefix(hostname)

    # wrap it into the generic extension wrapper
    #  (type- and length- prefix, 2B for each)
    extension = ExtensionType.server_name.value + lenprefix(snlist)
    return extension


def crext_MaxFragmentLength(length_exponent):
    """Create a MaxFragmentLength extension.
    Allowed lengths are 2^9, 2^10, 2^11, 2^12. (TLS default is 2^14)
    `length_exponent` should be 9, 10, 11, or 12, otherwise the extension will
    contain an illegal value.
    """
    maxlen = (length_exponent-8).to_bytes(1,"big")
    return ExtensionType.max_fragment_length.value + lenprefix(maxlen)


def crext_ClientCertificateURL():
    """Create a Client Certificate URL extension."""
    return ExtensionType.client_certificate_url.value + lenprefix(b"")


def crext_TruncatedHMAC():
    """Create a Truncated HMAC extension."""
    return ExtensionType.truncated_hmac.value + lenprefix(b"")


def crext_CertificateStatusRequest():
    """Create a Certificate Status Request (OCSP stapling) extension"""
    extension = (b"\x01"     # CertificateStatusType is OCSP (0x01)
                + lenprefix(b"")  # responderID list and request extensions
                + lenprefix(b"")) # (both empty -- known by "prior arrangement";
                                  #   works for Firefox, anyway)
    return ExtensionType.status_request.value + lenprefix(extension)


def crext_UserMapping():
    """Create a User Mapping extension"""
    extension_data = lenprefix(b"\x40")  # UserMappingTypeList;
                                # there is just one user mapping type.
                                # (upn_domain_hint, value 64)
    return ExtensionType.user_mapping.value + lenprefix(extension_data)


def crext_CertificateType(types):
    """Create a Certificate Type extension.
    `types` can take values "X.509", "OpenPGP", and "both"."""
    assert types in ["both", "X.509", "OpenPGP"]
    typelist = b""
    if types in ["X.509", "both"]:   typelist += b"\x00"
    if types in ["OpenPGP", "both"]: typelist += b"\x01"
    typelist = lenprefix(typelist,1)
    return ExtensionType.cert_type.value + lenprefix(typelist)


def crext_SupportedGroups():
    """Create a Supported Groups (formerly Elliptic Curves) extension.
    Includes ALL defined curves."""
    extension_data = lenprefix(b"".join(ec.value for ec in NamedCurve))
    return ExtensionType.supported_groups.value + lenprefix(extension_data)


def crext_ECPointFormats():
    """Create an ec_point_formats extension, with all the formats in it."""
    extension_data = lenprefix(b"\x00\x01\x02",1)
    return ExtensionType.ec_point_formats.value + lenprefix(extension_data)


def crext_Heartbeat(supported=True):
    """Create a Heartbeat extension.
    If `supported` is true, the extension indicates that the peer is allowed
     to send Heartbeats.
    """
    if supported:
        return ExtensionType.heartbeat.value + lenprefix(b"\x01")
    else:
        return ExtensionType.heartbeat.value + lenprefix(b"\x02")


def crext_ALPN(protocol="both"):
    """Create an ALPN extension.
    `protocol` can take values "http/1.1", "http/2", and "both"."""
    assert protocol in ["both", "http/1.1", "http/2"]
    namelist = b""
    if protocol in ["http/2", "both"]:   namelist += lenprefix(b"h2", 1)
    if protocol in ["http/1.1", "both"]: namelist += lenprefix(b"http/1.1", 1)
    namelist = lenprefix(namelist)
    return ExtensionType.application_layer_protocol_negotiation.value + lenprefix(namelist)


def crext_CertificateStatusRequestv2():
    """Create an OCSP multi-stapling extension"""
    item = (b"\x01"             # 0x01 for ocsp, 0x02 for ocsp_multi
            + lenprefix(
                lenprefix(b"") + lenprefix(b"")   # empty OCSPStatusRequest, as before
            ))
    # `item` here is basically a v1 request,
    #  with two length bytes added after status_type (0x01/0x02).
    # The v2 request contains a list of such items.
    itemlist = lenprefix(item)
    return ExtensionType.status_request_v2.value + lenprefix(itemlist)


def crext_SignedCertificateTimestamp():
    """Create an (empty) Signed Certificate Timestamp extension."""
    return ExtensionType.signed_certificate_timestamp.value + lenprefix(b"")


def crext_SessionTicket():
    """Create an (empty) Session Ticket TLS extension"""
    return ExtensionType.session_ticket_TLS.value + lenprefix(b"")


def crext_EncryptThenMAC():
    """Create an Encrypt-then-MAC extension"""
    return ExtensionType.encrypt_then_mac.value + lenprefix(b"")


def crext_ExtendedMasterSecret():
    """Create an Extended Master Secret extension"""
    return ExtensionType.extended_master_secret.value + lenprefix(b"")


def crext_RenegotiationInfo():
    """Create an (initial, empty) Renegotiation Info extension"""
    extension = lenprefix(b"", 1)
    return ExtensionType.renegotiation_info.value + lenprefix(extension)


class TLSExtension:
    """A generic TLS extension (appears in client/server hellos)"""
    def __init__(self, data):
        self.type   = ExtensionType.find(data[0:2])
        self.length = int.from_bytes(data[2:4], "big")
        self.data   = data[4:4+self.length]
        assert len(self.data) == self.length

        if not self.type:    # in case of unknown/new extension
            self.type = data[0:2]

    def __len__(self):
        return self.length


class ServerHello:
    """A server_hello.
    Parses itself from the provided bytestream, throws ValueError
    in case of malformed/incomplete record (but tolerates trailing bytes).
    """
    def __init__(self, bytestream):
        try:
            self.type    = HandshakeType.server_hello
            self.length  = int.from_bytes(bytestream[1:4], "big")
            self.version = SSLVersion.find(bytestream[4:6])
            self.random  = bytestream[6:38]

            session_id_len  = bytestream[38]
            assert session_id_len <= 32
            self.session_id = bytestream[39:39+session_id_len]

            bytestream = bytestream[39+session_id_len:]  # reset

            self.ciphersuite = CipherSuite.find(bytestream[0:2])
            self.compression_method = bytestream[2:3]

            self.extensions_length = 0
            self.extensions = []

            # extensions
            if len(bytestream) > 3:
                self.extensions_length = int.from_bytes(bytestream[3:5], "big")
                bytestream = bytestream[5:]
                assert len(bytestream) == self.extensions_length

                while bytestream:
                    ext = TLSExtension(bytestream)
                    self.extensions.append(ext)
                    bytestream = bytestream[4+len(ext):]
        except:
            raise ValueError("Malformed server hello")


class TLSRecord:
    """A single record of the TLS Record layer.
    Parses itself from the provided bytestream, throws ValueError
    in case of malformed/incomplete record (but tolerates trailing bytes).
    """
    def __init__(self, bytestream):
        try:
            assert len(bytestream) >= 6

            self.type = RecordType.find(bytestream[0:1])
            assert self.type, "Invalid record type"

            self.version = SSLVersion.find(bytestream[1:3])
            assert self.version, "Invalid SSL version"

            self.length = int.from_bytes(bytestream[3:5], "big")
            assert 5 + self.length <= len(bytestream), "Incomplete record"

            self.data = bytestream[5:5+self.length]
        except AssertionError as e:
            raise ValueError("Malformed TLS record") from e

    def __len__(self):
        return self.length




def create_client_hello(ssl_version, csuite_list, sni_url=None, max_ssl_version=None, extensions=b""):
    """Create a client hello (wrapped in a record) with the specified parameters.
    Arguments:
        `ssl_version`     -- the SSL/TLS version to put in handshake
        `csuite_list`     -- the list of ciphersuites to use
        `sni_url`         -- the URL for use in the SNI extension
                              (if falsy, SNI is not used)
        `max_ssl_version` -- the highest client-supported SSL/TLS version;
                              by default, `ssl_version` is used as both lowest and highest
        `extensions`      -- the extensions to add to handshake; a bytestring

    Returns a TLS record in the form of bytes.
    """

    csuites = b''.join( csuite.value for csuite in csuite_list )

    # First we build the client_hello itself
    hello = \
               ( (ssl_version.value          # max client-supported version
                    if not max_ssl_version
                    else   max_ssl_version.value)
                + os.urandom(32)  # (strictly speaking, first 4B should be GMT)
                + b'\x00'         # session_id length is 0 (i.e. no session ID)
                + lenprefix(csuites)
                + b'\x01'         # compression methods field length
                + b'\x00' )       # compression methods (only null compression)

    extension_list = []

    # usually necessary for connecting at all
    if sni_url:
        extension_list.append(crext_SNI(sni_url))

    # necessary for ECC support
    if any(["_EC" in cs.name for cs in csuite_list]):
        extension_list.append(crext_SupportedGroups())
        extension_list.append(crext_ECPointFormats())

    # the remaining extensions
    extension_list.append( extensions )

    hello += lenprefix(b"".join(extension_list))


    hello = HandshakeType.client_hello.value + lenprefix(hello, 3)

    # Then we build the record containing it
    hello_record = (
                RecordType.handshake.value
                + ssl_version.value                 # min client-supported version
                + lenprefix(hello))

    return hello_record


def try_handshake(url, client_hello):
    """Connect to server, send client hello, and return the server's raw reply.
    In case of failure, return False.
    """
    try:
        sock = socket.socket()
        sock.connect((url, 443))
    except OSError:
        try:
            sock.settimeout(10)
            sock.connect((url, 443))
        except:
            return False
    try:
        sock.send(client_hello)
        resp = sock.recv(100000)
    except OSError:
        return False
    finally:
        sock.close()

    return resp


def try_cipher(ssl_version, cipher, url="www.example.com"):
    """Check whether a cipher is supported on the given website,
    using the specified SSL/TLS version for the handshake.

    If `cipher` is falsy, this function checks whether the SSL/TLS version
    is supported at all.
    If `cipher` is a list, it checks whether at least one is supported.
    """

    if not cipher:             _ = [cs for cs in CipherSuite]
    elif type(cipher) != list: _ = [cipher]
    else:                      _ = cipher

    # start doing the handshake
    cHello = create_client_hello(ssl_version, _, url)
    resp = try_handshake(url, cHello)
    if not resp:
        return False

    # the first record should be the server hello
    try:
        reply = TLSRecord(resp)
    except:
        return False

    # check the server's reply
    try:
        # check record header and server hello
        assert reply.type == RecordType.handshake
        assert reply.version == ssl_version
        assert reply.data[0:1] == HandshakeType.server_hello.value
        sHello = ServerHello(reply.data)
        assert sHello.version == ssl_version

        # this should be enough for now
        return True

    except (AssertionError, ValueError) as e:
        return False


def try_protocol(ssl_version, url):
    """Check whether the given SSL/TLS version is supported."""
    if ssl_version == SSLVersion.SSLv2:
        return False    # TODO
    return try_cipher(ssl_version, None, url)


def extract_certificate_chain(cert_record : TLSRecord):
    """Extracts the certificate chain from the given record-layer Certificate
    record; returns a list of binary DER certificates"""

    assert cert_record.data[0:1] == HandshakeType.certificate.value
    length       = int.from_bytes(cert_record.data[1:4], "big")    # we ignore this one
    certs_length = int.from_bytes(cert_record.data[4:7], "big")

    certs = cert_record.data[7:]
    assert len(certs) == certs_length

    cert_list = []
    
    while certs:
        cert_len = int.from_bytes(certs[:3], "big")
        cert = certs[3:cert_len+3]
        assert len(cert) == cert_len

        cert_list.append(cert)
        certs = certs[cert_len+3:]

    return cert_list
    # return [asn1crypto.x509.Certificate.load(c) for c in cert_list)


def scan_all_extensions(ssl_version, url, delay=0.0):
    """Scan for support of all TLS extensions.
    Note: heartbeat detection should be improved by trying to send heartbeats.
    """
    # I don't think there *should* be interaction between some extensions
    #  (such as status_request and status_request_v2, for example),
    #  but I'm testing for them in separate handshakes anyway.

    supported = []

    # 0. Server name indication (SNI)
    cHello = create_client_hello(ssl_version, [cs for cs in CipherSuite], url)
    try:
        # expect server_hello with a server_name extension
        reply = TLSRecord(try_handshake(url, cHello))
        assert reply.type == RecordType.handshake
        assert reply.data[0:1] == HandshakeType.server_hello.value
        sHello = ServerHello(reply.data)
        assert any(e.type == ExtensionType.server_name for e in sHello.extensions)
        supported.append(ExtensionType.server_name)
    except:
        pass

    time.sleep(delay)

    # 1. Maximum fragment length
    cHello = create_client_hello(ssl_version, [cs for cs in CipherSuite], url,
               extensions = crext_MaxFragmentLength(12))
    try:
        # expect server_hello with a max_fragment_length extension
        reply = TLSRecord(try_handshake(url, cHello))
        assert reply.type == RecordType.handshake
        assert reply.data[0:1] == HandshakeType.server_hello.value
        sHello = ServerHello(reply.data)
        assert any(e.type == ExtensionType.max_fragment_length for e in sHello.extensions)
        supported.append(ExtensionType.max_fragment_length)
    except:
        # otherwise, check if it understands the extension at all
        cHello = create_client_hello(ssl_version, [cs for cs in CipherSuite], url,
                   extensions = crext_MaxFragmentLength(99))
        try:
            reply = TLSRecord(try_handshake(url, cHello))
            assert reply.type == RecordType.alert
            assert reply.data[1:2] == AlertType.illegal_parameter.value
            supported.append(ExtensionType.max_fragment_length)
        except:
            pass

    time.sleep(delay)

    # 4 (Truncated HMAC), 5 (OCSP stapling), 6 (User mapping)
    extensions = (crext_TruncatedHMAC()
                 + crext_CertificateStatusRequest()
                 + crext_UserMapping())
    cHello = create_client_hello(ssl_version, [cs for cs in CipherSuite], url, extensions=extensions)
    try:
        # expect server_hello with the extensions included
        reply = TLSRecord(try_handshake(url, cHello))
        assert reply.type == RecordType.handshake
        assert reply.data[0:1] == HandshakeType.server_hello.value
        sHello = ServerHello(reply.data)
        if any(e.type == ExtensionType.truncated_hmac for e in sHello.extensions):
            supported += [ExtensionType.truncated_hmac]
        if any(e.type == ExtensionType.status_request for e in sHello.extensions):
            supported += [ExtensionType.status_request]
        if any(e.type == ExtensionType.user_mapping for e in sHello.extensions):
            supported += [ExtensionType.user_mapping]
    except:
        pass

    time.sleep(delay)

    # 9. Certificate type
    cHello = create_client_hello(ssl_version, [cs for cs in CipherSuite], url,
               extensions = crext_CertificateType("OpenPGP"))
    try:
        # expect either server_hello with a cert_type extension,
        # or an unsupported_certificate fatal alert
        reply = TLSRecord(try_handshake(url, cHello))
        if reply.type == RecordType.alert and reply.data[1:2] == AlertType.unsupported_certificate:
            supported += [ExtensionType.cert_type]
        elif reply.type == RecordType.handshake:
            assert reply.data[0:1] == HandshakeType.server_hello.value
            sHello = ServerHello(reply.data)
            assert any(e.type == ExtensionType.cert_type for e in sHello.extensions)
            supported += [ExtensionType.cert_type]
    except:
        pass

    time.sleep(delay)

    # 15 (Heartbeat), 16 (ALPN), 17 (OCSP multi-stapling)
    extensions = (crext_Heartbeat()
                 + crext_ALPN()
                 + crext_CertificateStatusRequestv2())
    cHello = create_client_hello(ssl_version, [cs for cs in CipherSuite], url, extensions=extensions)
    try:
        # expect server_hello with the extensions included
        reply = TLSRecord(try_handshake(url, cHello))
        assert reply.type == RecordType.handshake
        assert reply.data[0:1] == HandshakeType.server_hello.value
        sHello = ServerHello(reply.data)
        if any(e.type == ExtensionType.heartbeat for e in sHello.extensions):
            supported += [ExtensionType.heartbeat]
        if any(e.type == ExtensionType.application_layer_protocol_negotiation for e in sHello.extensions):
            supported += [ExtensionType.application_layer_protocol_negotiation]
        if any(e.type == ExtensionType.status_request_v2 for e in sHello.extensions):
            supported += [ExtensionType.status_request_v2]
    except:
        pass

    time.sleep(delay)

    # 18 (SCT), 22 (Encrypt-then-MAC), 23 (Extended master secret),
    # 35 (Session ticket), 65281 (Renegotiation info)
    extensions = (crext_SignedCertificateTimestamp()
                + crext_EncryptThenMAC()
                + crext_ExtendedMasterSecret()
                + crext_SessionTicket()
                + crext_RenegotiationInfo())
    cHello = create_client_hello(ssl_version, [cs for cs in CipherSuite], url, extensions=extensions)
    try:
        # expect server_hello with the extensions included
        reply = TLSRecord(try_handshake(url, cHello))
        assert reply.type == RecordType.handshake
        assert reply.data[0:1] == HandshakeType.server_hello.value
        sHello = ServerHello(reply.data)
        if any(e.type == ExtensionType.signed_certificate_timestamp for e in sHello.extensions):
            supported += [ExtensionType.signed_certificate_timestamp]
        if any(e.type == ExtensionType.encrypt_then_mac for e in sHello.extensions):
            supported += [ExtensionType.encrypt_then_mac]
        if any(e.type == ExtensionType.extended_master_secret for e in sHello.extensions):
            supported += [ExtensionType.extended_master_secret]
        if any(e.type == ExtensionType.session_ticket_TLS for e in sHello.extensions):
            supported += [ExtensionType.session_ticket_TLS]
        if any(e.type == ExtensionType.renegotiation_info for e in sHello.extensions):
            supported += [ExtensionType.renegotiation_info]
    except:
        pass

    return supported



def scan_all_ciphers(ssl_version, url="www.example.com", delay=0.0):
    supported_csuites = []
    to_scan = []

    # check weak csuites
    print(url+" -- checking weak csuites", file=sys.stderr)
    if try_cipher(ssl_version, weak_csuites, url):
        to_scan += weak_csuites
    # check rare csuites
    print(url+" -- checking rare csuites", file=sys.stderr)
    if try_cipher(ssl_version, rare_csuites, url):
        to_scan += rare_csuites
    # check frequent csuites
    print(url+" -- checking freq csuites", file=sys.stderr)
    if try_cipher(ssl_version, frequent_csuites, url):
        to_scan += frequent_csuites

    print("starting scan of {} csuites...".format(len(to_scan)), file=sys.stderr)

    for csuite in to_scan:
        print(url+" -- scanning "+csuite.name, file=sys.stderr)
        ok = try_cipher(ssl_version, csuite, url)
        if ok:
            supported_csuites += [csuite]
        time.sleep(delay)

    return supported_csuites
