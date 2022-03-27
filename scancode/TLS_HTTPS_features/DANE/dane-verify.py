import argparse
import sys, os
import dns as mydns
import dns.message as mymessage
import base64
from OpenSSL import crypto
import hashlib
import json
import re
import subprocess
import struct
import time
import random
import shutil
import datetime

cert_path = "/etc/ssl/certs/"
make_name_size = 2 ** 16 - 1
root_certs = {}
chainMap = {}
chain_path = ""


def parseTLSA(raw):
    msg = base64.b64decode(raw)
    msg = mymessage.from_wire(msg)
    rrsetList = []

    for answer in msg.answer:
        if answer.rdtype == 52:
            rrsetList = rrsetList + [data.to_text() for data in answer]
    return rrsetList


def daneValid(d):
    from OpenSSL import crypto
    '''
    #Return
    -1: TLSA record does not exist
    -2: hava TLSA record, but https cert does not exist
    '''
    # resolve dns records, return tlsa record
    records = parseTLSA(d["tlsa"])
    # time = d['time'] + ":01:00"
    curr_time_str = time.strftime("%Y%m%d %H:%M:%S", time.localtime())
    dnssec = d["dnssec"]

    resultList = []
    for record in records:
        matched, chain, error = unitValidate(record, curr_time_str, d["cert_chain_list"])
        result = resultCase(dnssec, matched, chain)
        resultList.append(str(result))

    return ' '.join(resultList)


# selector = 0
def matchCrt(matching, data, crt):
    from OpenSSL import crypto

    if matching == '0':
        crt = crypto.load_certificate(crypto.FILETYPE_ASN1, crt)
        hashed = crypto.dump_certificate(crypto.FILETYPE_PEM, crt).lower().decode()
        hashed = hashed.replace('-----begin certificate-----', '').replace('-----end certificate-----', '').replace(
            '\n', '').lower()
        data = data.replace('-----begin certificate-----', '').replace('-----end certificate-----', '').replace('\n',
                                                                                                                '').lower()
    elif matching == '1':
        data = data.lower()
        hashed = hashlib.sha256(crt).hexdigest()
    elif matching == '2':
        data = data.lower()
        hashed = hashlib.sha512(crt).hexdigest()
    else:
        return False, "Matching-" + matching

    if hashed == data:
        return True, None
    return False, "CrtNotMatch"


def checkValidity(periods, time):
    currTime = datetime.datetime.strptime(time, "%Y%m%d %H:%M:%S")
    for period in periods:
        notBefore = datetime.datetime.strptime(period[0], "%Y%m%d-%H")
        notAfter = datetime.datetime.strptime(period[1], "%Y%m%d-%H")

        if currTime < notBefore:
            return False
        if currTime > notAfter:
            return False

    return True


def resultCase(dnssecRaw, matched, chain):
    if dnssecRaw == "Secure":
        dnssec = True
    else:
        dnssec = False

    if dnssec:
        if matched:
            if chain:
                return 0
            elif chain == "Empty":
                return 0
            else:
                return 1
        else:
            if chain:
                return 2
            elif chain == "Empty":
                return 3
            else:
                return 4
    else:
        if matched:
            if chain:
                return 5
            elif chain == "Empty":
                return 6
            else:
                return 7
        else:
            if chain:
                return 8
            elif chain == "Empty":
                return 9
            else:
                return 10


def chainValid(usage, time, certs):
    hashList = []
    for crt in certs:
        pem = base64.b64decode(crt)
        hashed = hashlib.sha256(pem).hexdigest()
        hashList.append(hashed)
    key = tuple(hashList)

    if usage == '0' or usage == '1':
        if key in chainMap:
            validity = checkValidity(chainMap[key]['periods'], time)  # 检查证书是否过期
            if validity:
                return chainMap[key]['usage0'], None  # 从chain-validation里面将结果取出来
            else:
                return False, "InvalidTime"
        else:
            return None, "NoKey"

    elif usage == '2':
        if len(certs) == 1:
            return False, "NoChain"
        else:
            if key in chainMap:
                validity = checkValidity(chainMap[key]['periods'], time)
                if validity:
                    return chainMap[key]['usage2'], None
                else:
                    return False, "InvalidTime"
            else:
                return None, "NoKey"
    else:
        return False, "WrongUsage"


def findRoot(cert):
    from OpenSSL import crypto
    crt = base64.b64decode(cert)
    crt = crypto.load_certificate(crypto.FILETYPE_PEM, crt)
    issuer = crt.get_issuer()

    if issuer == None:
        return None

    roots = set(root_certs.keys())

    if issuer.CN in roots:
        root = base64.b64encode(root_certs[issuer.CN].encode())
        return root
    return None


# selector = 1
def matchKey(matching, data, key):
    from OpenSSL import crypto
    if matching == '0':
        hashed = crypto.load_publickey(crypto.FILETYPE_ASN1, key)
        hashed = crypto.dump_publickey(crypto.FILETYPE_PEM, hashed).lower().decode()
        hashed = hashed.replace('-----begin public key-----', '').replace('-----end public key-----', '').replace('\n',
                                                                                                                  '').lower()
        data = data.replace('-----begin public key-----', '').replace('-----end public key-----', '').replace('\n',
                                                                                                              '').lower()
    elif matching == '1':
        data = data.lower()
        hashed = hashlib.sha256(key).hexdigest()
    elif matching == '2':
        data = data.lower()
        hashed = hashlib.sha512(key).hexdigest()
    else:
        return False, "Matching-" + matching

    if hashed == data:
        return True, None
    return False, "KeyNotMatch"


def isRoot(cert):
    from OpenSSL import crypto
    crt = base64.b64decode(cert)
    crt = crypto.load_certificate(crypto.FILETYPE_PEM, crt)
    issuer = crt.get_issuer()
    subject = crt.get_subject()

    if issuer == None or subject == None:
        return False

    if issuer.CN == subject.CN:
        return True
    return False


def unitValidate(record, time, certs):
    from OpenSSL import crypto

    record = record.split()
    if len(record) != 4:
        record = record[:3] + [''.join(record[3:])]
    usage = record[0]
    selector = record[1]
    matching = record[2]
    data = record[3]

    error = None
    chain = "Empty"
    if usage == '1' or usage == '3':

        pem = base64.b64decode(certs[0])
        crt = crypto.load_certificate(crypto.FILETYPE_PEM, pem)
        # use entire certificate
        if selector == '0':
            crt = crypto.dump_certificate(crypto.FILETYPE_ASN1, crt)
            matched, error = matchCrt(matching, data, crt)
            if usage == '1':
                chain, error = chainValid(usage, time, certs)
                if error == "NoKey":
                    chain = "NoKey"
            return matched, chain, error

        # use public key
        elif selector == '1':
            pubKey = crt.get_pubkey()
            pubKey = crypto.dump_publickey(crypto.FILETYPE_ASN1, pubKey)
            matched, error = matchKey(matching, data, pubKey)
            if usage == '1':
                chain, error = chainValid(usage, time, certs)
                if error == "NoKey":
                    chain = "NoKey"
            return matched, chain, error
        else:
            return False, chain, "Selector-" + selector
    elif usage == '0':
        if isRoot(certs[-1]):  # 总的来说在找根证书
            tmpCerts = certs
        else:
            root = findRoot(certs[-1])
            if root is None:
                tmpCerts = certs
            else:
                tmpCerts = certs + [root]
        for cert in tmpCerts[1:]:
            pem = base64.b64decode(cert)
            crt = crypto.load_certificate(crypto.FILETYPE_PEM, pem)

            chain, error = chainValid(usage, time, certs)
            if error == "NoKey":
                chain = "NoKey"
            if selector == '0':
                crt = crypto.dump_certificate(crypto.FILETYPE_ASN1, crt)
                matched, error = matchCrt(matching, data, crt)
                if matched:
                    return matched, chain, error
            elif selector == '1':
                pubKey = crt.get_pubkey()
                pubKey = crypto.dump_publickey(crypto.FILETYPE_ASN1, pubKey)
                matched, error = matchKey(matching, data, pubKey)
                if matched:
                    return matched, chain, error
            else:
                return False, chain, "Selector-" + selector

        return False, chain, error
    elif usage == '2':

        pem = base64.b64decode(certs[-1])
        crt = crypto.load_certificate(crypto.FILETYPE_PEM, pem)

        chain, error = chainValid(usage, time, certs)
        if error == "NoKey":
            chain = "NoKey"

        # use entire certificate
        if selector == '0':
            crt = crypto.dump_certificate(crypto.FILETYPE_ASN1, crt)
            matched, error = matchCrt(matching, data, crt)
            return matched, chain, error
        elif selector == '1':
            pubKey = crt.get_pubkey()
            pubKey = crypto.dump_publickey(crypto.FILETYPE_ASN1, pubKey)
            matched, error = matchKey(matching, data, pubKey)
            return matched, chain, error
        else:
            return False, chain, "Selector-" + selector
    else:
        return False, False, "Usage-" + usage


def getChains():
    global chainMap
    # files = os.listdir(chain_path)
    # if "_SUCCESS" in files:
    #     files.remove("_SUCCESS")

    initChainMap()

    # for filename in files:
    f = open(chain_path, "r")
    while True:
        line = f.readline()
        if not line: break
        line = line[:-1]

        if line == "None":
            continue
        line = line.split()  # 默认空格

        data = line[:-2]
        if line[-2] == "True":
            usage0Result = True  # 对应usage 0
        else:
            usage0Result = False
        if line[-1] == "True":
            usage2Result = True
        else:
            usage2Result = False

        certs = tuple(data[0::3])  # 只取的第1和第4列
        periods = list(zip(data[1::3], data[2::3]))  # certs和periods的映射
        if certs in chainMap:
            print("certExist!!!!")
            # exit()
        else:
            chainMap[certs] = {"periods": periods, "usage0": bool(usage0Result), "usage2": bool(usage2Result)}

    f.close()


def getRootCerts():
    global root_certs

    files = os.listdir(cert_path)
    if "java" in files:
        files.remove("java")

    for filename in files:
        f = open(cert_path + filename, "r")
        cert = f.read()
        crt = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        issuer = crt.get_issuer().CN

        root_certs[issuer] = cert
        f.close()

def initChainMap():
    global chainMap

    chainMap = {}

def dane_stat(result):
    if "0" in result:
        return True, "no_err"
    elif "5" in result:
        return False, "insecure"
    elif "1" in result or "6" in result or "7" in result:
        return False, "chain_err"
    elif "2" in result or "8" in result:
        return False, "match_err"
    elif "3" in result or "4" in result or "9" in result or "10" in result:
        return False, "chain_match_err"


def main(args):
    global root_certs, chain_path

    parser = argparse.ArgumentParser(description="Merge TLSA records and certificates to validate DANE")
    parser.add_argument('merge_file', help="Input file containing tlsa and cert merge result")
    parser.add_argument('chain_file', help="Input file containing a list of chain result")
    parser.add_argument('output', help="Output dir to write results to")

    args = parser.parse_args(args)
    chain_path = args.chain_file

    getRootCerts()

    getChains()

    in_f = open(args.merge_file)

    with open(args.output, 'w') as out_f:
        out_f.write("ip,domain,dnssec,dane,err" + "\n")
        while True:
            line = in_f.readline()
            if not line: break
            data = json.loads(line)

            if data["tlsa"] == "" or data["cert_chain"] == "":
                continue

            ip = data["ip"]
            domain = data["domain"]
            dnssec = data["dnssec"]

            data["cert_chain_list"] = data["cert_chain"].split(",")

            dane_Valid_Result = daneValid(data)

            stat_result, err = dane_stat(dane_Valid_Result)

            out_f.write(ip + "," + domain + "," + dnssec + "," + str(stat_result) + "," + err + "\n")

    out_f.close()


if __name__ == "__main__":
    main(sys.argv[1:])
