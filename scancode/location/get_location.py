import argparse
import json
import sys
import time
import urllib.request
import urllib.parse

def main(args):
    parser = argparse.ArgumentParser(description="Running a series of dns queries on a list of IPs")
    parser.add_argument('input', help="Input file containing a list of IPs")
    parser.add_argument('output', help="Output dir to write results to")
    args = parser.parse_args(args)
    start = time.time()
    print(start)
    f_in = open(args.input)
    with open(args.output, 'w') as out_file:
        # out_file.write("ip,X,Y" + "\n")
        raw = f_in.readlines()
        for line in raw:
            ip = line.rstrip("\n")
            # headers = {'User-Agent': 'User-Agent:Mozilla/5.0'}
            url = "http://ip-api.com/json/" + ip
            try:
                res = urllib.request.urlopen(url)
                if res.status == 200:
                    json_data = json.loads(res.read().decode('UTF-8'))
                    if json_data["status"] == "success":
                        print(ip)
                        out_file.write(json.dumps(json_data) + "\n")
                    # else:
                    #     out_file.write(ip + "," + "not found" + "\n")
                    # time.sleep(1)
                elif res.status == 429:
                    print(ip, "qps限制，等待1s")
                    raw.append(ip)
                    time.sleep(1)
                else:
                    out_file.write(ip + "," + "error" + "\n")
            except Exception:
                print(ip, "qps限制，等待1s")
                raw.append(ip)
                time.sleep(1)

    f_in.close()
    out_file.close()
    end = time.time()
    print("耗时", end - start)


if __name__ == "__main__":
    main(sys.argv[1:])



