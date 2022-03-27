"""
    代码作用为合并DOT的TLSA记录和对应证书链，用于验证DANE
    输入依次为TLSA文件，cert文件，输出文件。
    输出为json文件
"""

__author__ = "lrx"

import argparse
import sys
import json


def getTLSA(tlsafile, merge_dict):
    f = open(tlsafile, "r")

    while True:
        line = f.readline()
        if not line: break
        data = json.loads(line)

        if data["tlsa"] != "":
            key = data["domain"] + ":" + data["ip"]

            merge_dict[key] = {"domain": data["domain"], "ip": data["ip"], "tlsa": data["tlsa"],
                               "dnssec": data["tlsa_dnssec"]}

    return merge_dict


def getCert(certfile, merge_dict):
    f = open(certfile, "r")
    keys = merge_dict.keys()

    while True:
        line = f.readline()
        if not line: break
        data = json.loads(line)

        key = data["domain"] + ":" + data["ip"]
        if key in keys:
            merge_dict[key]["cert_chain"] = data["raw_cert_chain"]

    return merge_dict


def main(args):
    global transport_type
    parser = argparse.ArgumentParser(description="Merge TLSA records and certificates to validate DANE")
    parser.add_argument('tlsa_file', help="Input file containing a list of TLSA records")
    parser.add_argument('cert_file', help="Input file containing a list of certificate")
    parser.add_argument('output', help="Output dir to write results to")

    args = parser.parse_args(args)

    merge_dict = {}
    merge_dict = getTLSA(args.tlsa_file, merge_dict)
    merge_dict = getCert(args.cert_file, merge_dict)

    fOut = open(args.output, "w")

    for key in merge_dict.keys():
        if merge_dict[key]["cert_chain"] != "":
            json.dump(merge_dict[key], fOut)
            fOut.write("\n")


if __name__ == "__main__":
    main(sys.argv[1:])
