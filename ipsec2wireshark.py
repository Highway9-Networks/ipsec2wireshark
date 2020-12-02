#!/usr/bin/env python3
"""
Runs "ip xfrm state" and outputs lines to be added to ~/.wireshark/esp_sa
This process must be run using sudo.

This allows Wireshark to decrypt ipsec traffic captured with 'sudo tcpdump -vni any -U -w /tmp/esp.pcap "ip proto 50"'
"""

import sys
import subprocess

AUTH = {
    ("hmac(md5)", "96"): "HMAC-MD5-96 [RFC2403]",
    ("hmac(rmd160)", "96"): "MAC-RIPEMD-160-96 [RFC2857]",
    ("hmac(sha1)", "96"): "HMAC-SHA-1-96 [RFC2404]",
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
    "cbc(aes)": "AES-CBC [RFC3602]",
    "rfc4106(gcm(aes))": "AES-GCM [RFC4106]",
}


def parse_xfrm(ip=None):
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
    """
    connections = []
    connection = None
    for line in subprocess.check_output(
            ["ip", "xfrm", "state"], encoding=sys.stdout.encoding).split("\n"):
        if line.startswith("src "):
            if connection is not None:
                connections.append(connection)
            if ip is None or ip in line:
                _, src, _, dst = line.split(" ")
                connection = {"src": src, "dst": dst}
            else:
                connection = None
        elif connection is not None:
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

    if connection is not None:
        connections.append(connection)

    return connections


def output_wireshark(connections):
    """Output ~/.wireshark/esp_sa lines of the form
    "IPv4","10.0.0.161","69.27.252.3","0x66a336c8","AES-CBC [RFC3602]","0xc033ab0b0b7d0b28841ffc8c2746da60a6cfd32c19fcfcddbd0e318c430a94cd","HMAC-SHA-1-96 [RFC2404]","0x0472ec471f7342db23904ccae9091303c710a318"
    "IPv4","69.27.252.3","10.0.0.161","0xc36ee45f","AES-CBC [RFC3602]","0xbadc9e716a0cdb11cd86f7c4986e5a70200fd353ed06b2ee30680fb7c6bd320d","HMAC-SHA-1-96 [RFC2404]","0xccd0880af3650626adda310aa385661c6e100ec0"
    """
    for connection in connections:
        print('"IPv4","{src}","{dst}","{spi}","{enc}","{enc_key}","{auth}","{auth_key}"'.format(**connection))


if __name__ == "__main__":
    ip = sys.argv[1] if len(sys.argv) > 1 else None
    connections = parse_xfrm(ip)
    output_wireshark(connections)
