"""
    代码作用为验证证书链是否有效
    输入依次为输入文件，根证书文件，输出文件，临时目录。
    输出为csv文件
"""
__author__ = "lrx"

import argparse
import string
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

make_name_size = 2 ** 16 - 1
root_certs = ''
temp_path = ""  # ex) /run/shm/john, Temporary path for chain validation. Temporary certificates are generated in


def make_name():
    global make_name_size
    return struct.pack(">dHI", time.time(), random.randint(0, make_name_size), os.getpid()).hex()




# 获取每个证书的颁发时间和过期时间
def getCerts(data):
    from OpenSSL import crypto

    def getCertRecord(certs):
        periodList = []
        # certs = certs.split(",")
        for crt in certs:
            pem = base64.b64decode(crt)
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, pem)  # 从类型为type编码的字符串缓冲区加载证书 (X509)
            notBefore = datetime.datetime.strptime(cert.get_notBefore().decode(), "%Y%m%d%H%M%SZ")
            notAfter = datetime.datetime.strptime(cert.get_notAfter().decode(), "%Y%m%d%H%M%SZ")
            periodList.append((notBefore, notAfter))

        return periodList

    if data['cert_chain'] == "":
        return {"name": "none"}

    certs = data['cert_chain_list']
    periodList = getCertRecord(certs)  # 获取证书的时间

    result = {"name": " ".join(certs), "certs": certs, "periods": periodList}

    return result


# 验证证书链，通过使用openssl
def chainVerify(usage, time, certs):
    from OpenSSL import crypto

    global temp_path, root_certs
    '''
    #Return
    False (Chain is invalid)
    True (Chain is valid)
    '''

    certNum = len(certs)
    leaf = base64.b64decode(certs[0]).decode()

    while True:
        tmp_folder = "ssl_verify_" + make_name()
        base_path = os.path.join(temp_path, tmp_folder)
        if not os.path.isdir(base_path):
            os.makedirs(base_path)
            break

    leaf_filename = os.path.join(base_path, "leaf.pem")
    f_leaf = open(leaf_filename, "w")
    f_leaf.write(leaf)
    f_leaf.close()

    root_filename = os.path.join(base_path, "root.pem")
    f_root = open(root_filename, "w")
    f_root.write(root_certs)
    f_root.close()

    eTime = datetime.datetime.strptime(time, "%Y%m%d %H:%M:%S")
    eTime = str(int(eTime.timestamp()))

    if certNum == 1:
        if usage == "0" or usage == "1":  # 在证书链只有一个证书且usage为0或1时，root_filename = root-ca-list ，leaf_filename为该证书
            query = ['openssl', 'verify', '-CAfile', root_filename, leaf_filename]
        else:  # 在证书链只有一个证书且usage为2或3时，证书链验证失败
            shutil.rmtree(base_path)
            return False, ""
    else:
        inter = ""
        if usage == "0" or usage == "1":  # 在证书链多余一个证书且usage为0或1时，root_filename = root-ca-list ，leaf_filename = certs[0] ,inter_filename为将剩余证书链接，以换行符分割
            for cert in certs[1:]:
                inter = inter + base64.b64decode(cert).decode() + "\n"

            inter_filename = os.path.join(base_path, "inter.pem")
            f_inter = open(inter_filename, "w")
            f_inter.write(inter)
            f_inter.close()

            query = ['openssl', 'verify', '-CAfile', root_filename, '-untrusted', inter_filename, leaf_filename]

        else:  # 在证书链多余一个证书且usage为2或3时，root_filename = certs[-1](新的根证书) ，leaf_filename = certs[0] ,inter_filename为将剩余证书链接，以换行符分割
            root = base64.b64decode(certs[-1]).decode()
            root_filename = os.path.join(base_path, "root.pem")
            f_root = open(root_filename, "w")
            f_root.write(root)
            f_root.close()

            for cert in certs[1:-1]:
                inter = inter + base64.b64decode(cert).decode() + "\n"

            if inter == "":
                query = ['openssl', 'verify', '-CAfile', root_filename, leaf_filename]
            else:
                inter_filename = os.path.join(base_path, "inter.pem")
                f_inter = open(inter_filename, "w")
                f_inter.write(inter)
                f_inter.close()

                query = ['openssl', 'verify', '-CAfile', root_filename, '-untrusted', inter_filename, leaf_filename]

    process = subprocess.Popen(query, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdoutdata, stderrdata = process.communicate()
    result = stdoutdata.decode()
    #print(result)
    shutil.rmtree(base_path)
    fails = ["error", "fail", "Error", "Expire"]
    for fail in fails:
        if fail in result:
            return False, result

    return True, stderrdata.decode()


def chainValid(data):
    if data[0] == "None":
        return "None"

    rawData = [t for t in data[1]]
    periodList = rawData[0]['periods']
    certList = rawData[0]['certs']

    time = periodList[0][0] + datetime.timedelta(hours=1)
    time = time.strftime("%Y%m%d %H:%M:%S")

    isValid0, error0 = chainVerify('0', time, certList)
    isValid2, error2 = chainVerify('2', time, certList)
    #print(error0)
    #print(error2)

    hashList = []

    for crt in certList:
        pem = base64.b64decode(crt)
        hashed = hashlib.sha256(pem).hexdigest()  # sha256哈希
        hashList.append(hashed)

    result = ""
    for hashed, period in zip(hashList, periodList):
        result = result + hashed + " " + period[0].strftime("%Y%m%d-%H") + " " + period[1].strftime("%Y%m%d-%H") + " "

    result = result + str(isValid0) + " " + str(isValid2)
    return result


def saveAsTextFile(tem_data, filename):
    tf = open(filename, "a")
    tf.writelines(tem_data + "\n")


def main(args):
    from itertools import groupby
    from operator import itemgetter
    global root_certs, temp_path

    parser = argparse.ArgumentParser(description="Merge TLSA records and certificates to validate DANE")
    parser.add_argument('cert_file', help="Input file containing a list of Certificate")
    parser.add_argument('root_file', help="Input file containing a list of Root Certificate")
    parser.add_argument('output', help="Output dir to write results to")
    parser.add_argument('tempdir', help="temp dir to write results to")

    args = parser.parse_args(args)

    temp_path = args.tempdir

    f_root = open(args.root_file, "r")
    root_certs = f_root.read()
    f_root.close()
    tem_database = []

    in_f = open(args.cert_file, "r")

    while True:
        line = in_f.readline()
        if not line: break
        data = json.loads(line)
        data["cert_chain_list"] = data["cert_chain"].split(",")
        getCerts_results = getCerts(data)
        if getCerts_results == "none":
            continue
        tem_database.append(getCerts_results)

    res = groupby(tem_database, key=itemgetter("name"))
    tem_database_groupby = {name: list(item) for name, item in res}

    tem_filename = "result_chain_valid.txt"

    for key, value in tem_database_groupby.items():
        line = [key, value]
        # print("line:",line)
        chainValidSet_results = chainValid(line)
        saveAsTextFile(chainValidSet_results, args.output + tem_filename)


if __name__ == "__main__":
    main(sys.argv[1:])
