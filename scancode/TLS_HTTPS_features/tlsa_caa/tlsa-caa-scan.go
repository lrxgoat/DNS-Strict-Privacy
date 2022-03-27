/*
	代码使用unbound获取域名的TLSA和CAA记录，并验证响应是否受DNSSEC保护。
	输入为(ip,domain)形式的文件，参数分别为线程数，输入文件，输出文件夹。
	ex: go run tlsa-caa-scan.go 100 ./domain.txt ./result/

	输出为json文件

	注：在853端口扫描TLSA记录，域名格式为_853._tcp.domain	or _853._tcp.www.domain

*/
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	"github.com/miekg/unbound"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ScanResult struct{
	Domain			string	`json:"domain"`
	Ip				string	`json:"ip"`
	TLSA			string	`json:"tlsa"`		// tlsa记录
	CAA				string	`json:"caa"`		// caa记录
	TLSADnssec		string	`json:"tlsa_dnssec"`	// secure, bogus+whybogus, insecure
	CAADnssec		string	`json:"caa_dnssec"`
	TLSAError		string	`json:"tlsa_error"`
	CAAError		string	`json:"caa_error"`
}

func main() {
	args := os.Args[1:]
	numThreads, _ := strconv.Atoi(args[0]) // the number of threads
	inputFile := args[1] // seed file
	outputPath := args[2] // path of the output file

	u := unbound.New()
	defer u.Destroy()

	slabs := "256"

	startTime := time.Now()
	fmt.Println("start scan at:", startTime)

	if err := u.Hosts("/etc/hosts"); err != nil {
		log.Fatalf("error %s\n", err.Error())
	}

	if err := u.AddTaFile("/var/lib/unbound/root.key"); err != nil {
		log.Fatalf("error %s\n", err.Error())
	}

	if err := u.SetOption("qname-minimisation", "no"); err != nil {
		log.Fatalf("error %s\n", err.Error())
	}
	if err := u.SetOption("msg-cache-slabs", slabs); err != nil {
		log.Fatalf("error %s\n", err.Error())
	}
	if err := u.SetOption("rrset-cache-slabs", slabs); err != nil {
		log.Fatalf("error %s\n", err.Error())
	}
	if err := u.SetOption("infra-cache-slabs", slabs); err != nil {
		log.Fatalf("error %s\n", err.Error())
	}
	if err := u.SetOption("key-cache-slabs", slabs); err != nil {
		log.Fatalf("error %s\n", err.Error())
	}
	if err := u.SetOption("rrset-cache-size", "50m"); err != nil {
		log.Fatalf("error %s\n", err.Error())
	}
	if err := u.SetOption("msg-cache-size", "25m"); err != nil {
		log.Fatalf("error %s\n", err.Error())
	}
	if err := u.SetOption("outgoing-range", "1024"); err != nil {
		log.Fatalf("error %s\n", err.Error())
	}
	if err := u.SetOption("num-queries-per-thread", "512"); err != nil {
		log.Fatalf("error %s\n", err.Error())
	}
	if err := u.SetOption("so-sndbuf", "4m"); err != nil {
		log.Fatalf("error %s\n", err.Error())
	}
	if err := u.SetOption("so-rcvbuf", "4m"); err != nil {
		log.Fatalf("error %s\n", err.Error())
	}
	if err := u.SetOption("do-ip6", "no"); err != nil {
		log.Fatalf("error %s\n", err.Error())
	}


	jobs := make(chan string)
	var wg sync.WaitGroup

	for w := 0; w < numThreads; w++ {
		wg.Add(1)
		go run(jobs, u, strconv.Itoa(w), outputPath, &wg)
	}

	inputf, err := os.Open(inputFile)
	if err != nil {
		println(err.Error())
	}
	scanner := bufio.NewScanner(inputf)

	for scanner.Scan() {
		jobs <- scanner.Text()
	}
	close(jobs)
	wg.Wait()

	endTime := time.Now()
	fmt.Println("end scan at:", endTime)
	fmt.Println("duration:", time.Since(startTime).String())

}

func run(jobs <- chan string, u *unbound.Unbound, idx string, outputPath string, wg *sync.WaitGroup){
	defer wg.Done()

	output := outputPath + "tlsa-caa-" + idx + ".txt"
	f, err:= os.Create(output)
	if err != nil {
		println("Cannot write output -", outputPath)
	}


	for line := range jobs {
		target := new(ScanResult)
		split := strings.Split(line, ",")
		target.Ip = split[0]
		target.Domain = split[1]

		tlsa_domain_1 := "_853._tcp." + target.Domain
		tlsa_domain_2 := "_853._tcp.www." + target.Domain // TLSA记录两种前缀格式，都进行一次请求

		tlsaresult1, err1 := u.Resolve(tlsa_domain_1, dns.TypeTLSA, dns.ClassINET)
		if err1 != nil {
			target.TLSAError = err1.Error()
		}

		tlsaresult2, err2 := u.Resolve(tlsa_domain_2, dns.TypeTLSA, dns.ClassINET)
		if err2 != nil {
			target.TLSAError = err2.Error()
		}

		caaresult, err3 := u.Resolve(target.Domain, dns.TypeCAA, dns.ClassINET)
		if err3 != nil {
			target.CAAError = err3.Error()
		}

		// TLSA
		// 先对第一种前缀进行请求，没有数据在对第二种前缀请求
		if tlsaresult1.HaveData{
			answer, _ := tlsaresult1.AnswerPacket.Pack()
			enc := base64.StdEncoding.EncodeToString(answer)
			target.TLSA = enc

			if tlsaresult1.Secure {
				target.TLSADnssec = "Secure"
			} else if tlsaresult1.Bogus {
				bogus := strings.Replace(tlsaresult1.WhyBogus, ",",";",-1)
				target.TLSADnssec = "Bogus#||#" + bogus
			}else {
				target.TLSADnssec = "Insecure"
			}
		}else if tlsaresult2.HaveData{
			answer, _ := tlsaresult2.AnswerPacket.Pack()
			enc := base64.StdEncoding.EncodeToString(answer)
			target.TLSA = enc

			if tlsaresult2.Secure {
				target.TLSADnssec = "Secure"
			} else if tlsaresult2.Bogus {
				bogus := strings.Replace(tlsaresult2.WhyBogus, ",",";",-1)
				target.TLSADnssec = "Bogus#||#" + bogus
			}else {
				target.TLSADnssec = "Insecure"
			}
		}

		// CAA

		if caaresult.HaveData{
			answer, _ := caaresult.AnswerPacket.Pack()
			enc := base64.StdEncoding.EncodeToString(answer)
			target.CAA = enc

			if caaresult.Secure{
				target.CAADnssec = "Secure"
			} else if caaresult.Bogus {
				bogus := strings.Replace(caaresult.WhyBogus, ",",";",-1)
				target.CAADnssec = "Bogus#||#" + bogus
			}else {
				target.CAADnssec = "Insecure"
			}
		}


		result, errjson := json.Marshal(target)
		if errjson != nil {
			fmt.Println("JsonError", err.Error())
		}
		f.Write(result)
		f.WriteString("\n")

	}


}
