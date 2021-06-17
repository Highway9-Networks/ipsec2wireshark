#!/usr/bin/env python3
#
# Copyright Andrew Wason <rectalogic@rectalogic.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

"""
Runs "ip xfrm state" and outputs lines to be added to ~/.wireshark/esp_sa
This process must be run using sudo.

This allows Wireshark to decrypt ipsec traffic captured with:
'sudo tcpdump -vni any -U -w /tmp/esp.pcap "ip proto 50"'
"""

import sys
import subprocess

AUTH = {
    ("null", "0"):   "NULL",
    ("hmac(md5)", "96"): "HMAC-MD5-96 [RFC2403]",
    ("hmac(rmd160)", "96"): "MAC-RIPEMD-160-96 [RFC2857]",
    ("hmac(sha1)", "96"): "HMAC-SHA-1-96 [RFC2404]",
    ("hmac(sha256)", "96"):
        "HMAC-SHA-256-96 [draft-ietf-ipsec-ciph-sha-256-00]",
    ("hmac(sha256)", "128"): "HMAC-SHA-256-128 [RFC4868]",
    ("hmac(sha384)", "192"): "HMAC-SHA-384-192 [RFC4868]",
    ("hmac(sha512)", "256"): "HMAC-SHA-512-256 [RFC4868]",
    ("", "64"): "ANY 64 bit authentication [no checking]",
    ("", "96"): "ANY 96 bit authentication [no checking]",
    ("", "128"): "ANY 128 bit authentication [no checking]",
    ("", "192"): "ANY 192 bit authentication [no checking]",
    ("", "256"): "ANY 256 bit authentication [no checking]",
}

ENC = {
    "ecb(cipher_null)": "NULL",
    "cbc(des3_ede)": "TripleDES-CBC [RFC2451]",
    "cbc(aes)": "AES-CBC [RFC3602]",
    "rfc3686(ctr(aes))": "AES-CTR [RFC3686]",
    "cbc(des)": "DES-CBC [RFC2405]",
    "cbc(cast5)": "CAST5-CBC [RFC2144]",
    "cbc(blowfish)": "BLOWFISH-CBC [RFC2451]",
    "cbc(twofish)": "TWOFISH-CBC",
    "rfc4106(gcm(aes))": "AES-GCM [RFC4106]",
}


def main():
    """Parse ip xfrm state and output ~/.wireshark/esp_sa lines."""
    ip_address = sys.argv[1] if len(sys.argv) > 1 else None
    connections = parse_xfrm(ip_address)
    output_wireshark(connections)


def parse_xfrm(ip_address=None):
    # pylint: disable=line-too-long
    """Parse "ip xfrm state" output of the form
    src 10.0.0.161 dst 69.27.252.3
        proto esp spi 0x66a336c8 reqid 6 mode tunnel
        replay-window 32 flag af-unspec
        auth-trunc hmac(sha1) 0x0472ec471f7342db23904ccae9091303c710a318 96
        enc cbc(aes) 0xc033ab0b0b7d0b28841ffc8c2746da60a6cfd32c19fcfcddbd0e318c430a94cd
    src 69.27.252.3 dst 10.0.0.161
        proto esp spi 0xc36ee45f reqid 6 mode tunnel
        replay-window 32 flag af-unspec
        auth-trunc hmac(sha1) 0xccd0880af3650626adda310aa385661c6e100ec0 96
        enc cbc(aes) 0xbadc9e716a0cdb11cd86f7c4986e5a70200fd353ed06b2ee30680fb7c6bd320d
    src 2001:db8:0:f101::1 dst 2001:db8:0:f101::2
        proto esp spi 0xc51ae436 reqid 1 mode tunnel
        replay-window 0 flag af-unspec
        mark 0x20/0xffffffff
        auth-trunc hmac(sha256) 0xf4ed3e6cae060981d6e601bae460e6f3f7403c636fa457d0ed2cc7d84188e907 128
        enc cbc(aes) 0x698140d9e1ee3dc329476b6db6c815ac1dc81d5e4f6078654f86ded372dac830
        anti-replay context: seq 0x0, oseq 0x0, bitmap 0x00000000
    src 2001:db8:0:f101::2 dst 2001:db8:0:f101::1
        proto esp spi 0xcf5d891f reqid 1 mode tunnel
        replay-window 32 flag af-unspec
        auth-trunc hmac(sha256) 0x5869c6110e24897611942cbe166cbc611e99fab6521511d3c826c75281203f9b 128
        enc cbc(aes) 0x93231b97aff6c9d43dd17863e7b71be83a3a809f78d25a7d034313a645d587bd
        anti-replay context: seq 0x0, oseq 0x0, bitmap 0x00000000
    """
    # pylint: enable=line-too-long
    connections = []
    connection = {}
    for line in subprocess.check_output(
            ["ip", "xfrm", "state"], encoding=sys.stdout.encoding).split("\n"):
        if line.startswith("src "):
            if connection:
                connections.append(connection)
            if ip_address is None or ip_address in line:
                _, src, _, dst = line.split(" ")
                connection = {"src": src, "dst": dst}
            else:
                connection = {}
        elif connection:
            if line.startswith("\tproto esp"):
                connection["spi"] = line.split(" ")[3]
            elif line.startswith("\tauth-trunc "):
                _, auth, key, bits = line.split(" ")
                connection["auth"] = AUTH[(auth, bits)]
                connection["auth_key"] = key
            elif line.startswith("\tenc "):
                _, enc, key = line.split(" ")
                connection["enc"] = ENC[enc]
                connection["enc_key"] = key
            elif line.startswith("\taead"):
                _, enc, key, bits = line.split(" ")
                connection["enc"] = ENC[enc]
                connection["enc_key"] = key
                connection["auth"] = AUTH[("", bits)]
                connection["auth_key"] = ""
            # encap type espinudp sport 10002 dport 10001 addr 10.0.10.58
            elif line.startswith("\tencap"):
                parsed = line.split(" ")
                connection["port"] = parsed[4]
    if connection:
        connections.append(connection)

    return connections


def output_wireshark(connections):
    # pylint: disable=line-too-long
    """Output ~/.wireshark/esp_sa lines of the form
    "IPv4","10.0.0.161","69.27.252.3","0x66a336c8","AES-CBC [RFC3602]","0xc033ab0b0b7d0b28841ffc8c2746da60a6cfd32c19fcfcddbd0e318c430a94cd","HMAC-SHA-1-96 [RFC2404]","0x0472ec471f7342db23904ccae9091303c710a318"
    "IPv4","69.27.252.3","10.0.0.161","0xc36ee45f","AES-CBC [RFC3602]","0xbadc9e716a0cdb11cd86f7c4986e5a70200fd353ed06b2ee30680fb7c6bd320d","HMAC-SHA-1-96 [RFC2404]","0xccd0880af3650626adda310aa385661c6e100ec0"
    """
    # pylint: enable=line-too-long

    for connection in connections:
        ip_version = 'IPv6' if ':' in connection['src'] else 'IPv4'
        print(
            '"{ip_version}","{src}","{dst}","{spi}","{enc}","{enc_key}","{auth}",'
            '"{auth_key}"'.format(ip_version=ip_version, **connection))


if __name__ == "__main__":
    main()
