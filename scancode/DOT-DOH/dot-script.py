"""
    代码作用为筛选DOT解析器。使用dnspython库在853端口上向ip发出DNS请求。成功响应的则为DOT解析器。
    输入为IP文件，输出为两个文件。一个为是DOT的ip，另一个为不是DOT的ip。
"""

__author__ = "lrx"

import multiprocessing as mp
from tqdm import tqdm
import argparse
import sys
import dns.resolver  # https://github.com/byu-imaal/dnspython
import dns.exception

transport_type = "tls"  # 传输类型

base_domain = "www.example.com"  # 向解析器查询的域名


def check_dnspython():
    """
    确保为修改后的dnspython库
    """
    if "transport" not in dns.resolver.query.__code__.co_varnames:
        print("Not using modified dnspython with tls support")
        exit(1)


# 查询主函数
def query(target):
    target = target.strip('\n')
    data = {"ip": target, "flag": False}

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [target]
    resolver.port = 853  # DOT端口

    try:
        answers = resolver.query(base_domain, "A", transport=transport_type, lifetime=4)  # 发起DNS请求
    except Exception as ex:
        # 出现这些错误，可以认为解析器有响应
        # if any([isinstance(ex, e) for e in
        #         [dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.NoAnswer, dns.resolver.NotAbsolute]]):
        #     data["flag"] = True
        return data
    if len(answers) > 0:
        data["flag"] = True

    return data


def main(args):
    global transport_type
    parser = argparse.ArgumentParser(description="Running a series of dns queries on a list of IPs")
    parser.add_argument('input', help="Input file containing a list of IPs")
    parser.add_argument('output', help="Output dir to write results to")
    parser.add_argument('-n', '--num-threads', help="Number of threads to execute queries", default=64, type=int)
    parser.add_argument('-p', '--position_bar',
                        help="The position of the tqdm progress bar. Used when running multiple", type=int, default=0)

    args = parser.parse_args(args)
    check_dnspython()

    in_file = open(args.input)  # 读取输入文件
    targets = in_file.readlines()
    if not targets[0][0].isdecimal():
        targets = targets[1:]
    in_file.close()

    have_path = args.output + "have_dot.txt"  # 定义文件名称
    no_path = args.output + "no_dot.txt"

    threads = min(args.num_threads, len(targets))

    with open(have_path, 'w') as have_file, open(no_path, 'w') as no_file:
        with mp.Pool(processes=threads) as p:
            try:
                for result in tqdm(p.imap_unordered(query, targets), total=len(targets),
                                   desc="{} ({} threads)".format("dot-check", threads), position=args.position_bar):
                    # 写入文件
                    if result["flag"]:
                        have_file.write(result["ip"] + "\n")
                    else:
                        no_file.write(result["ip"] + "\n")
            except KeyboardInterrupt:
                p.terminate()
                p.join()
                print("Exiting early from queries. Current results will still be written")


if __name__ == "__main__":
    main(sys.argv[1:])
