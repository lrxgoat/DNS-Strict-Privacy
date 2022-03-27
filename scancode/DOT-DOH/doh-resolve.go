package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"github.com/miekg/dns"
	//"github.com/tumi8/tls"
	"golang.org/x/net/context"
	"golang.org/x/time/rate"
	"net/http"
	"os"
	"runtime"
	"strconv"
	_ "strings"
	"sync"
	"time"
)


const(
	QueryDomain = "example.com"
	DohJsonType = "application/dns-json"
	DohDnsType = "application/dns-message"
	GetQuery = "?dns=q80BAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB"
	JsonQuery = "?name=example.com&type=A"
)

func init(){
	runtime.GOMAXPROCS(runtime.NumCPU())
}

type ScanResult struct {
	Ip		string	`json:"ip"`
	Suffix	string	`json:"suffix"`
	ResFlag	bool	`json:"res_flag"`
	GetH1	bool	`json:"get_h1"`
	GetH2	bool	`json:"get_h2"`
	PostH1	bool	`json:"post_h1"`
	PostH2	bool	`json:"post_h2"`
	JsonH1	bool	`json:"json_h1"`
	JsonH2	bool	`json:"json_h2"`
}

func getDns(ip string, suffix string, proto string) bool {

	url := "https://" + ip + "/" + suffix + GetQuery
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	req.Proto = proto

	req.Header.Set("Content-Type", DohDnsType)
	//req.Header.Set("Accept", DohDnsType)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MaxVersion: 0,
		},
	}

	Client := http.Client{
		Timeout: 5 * time.Second,
		Transport: transport,
	}
	resp, err := Client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK && resp.Header.Get("Content-Type") == DohDnsType{
		return true
	}else{
		return false
	}
}

func postDns(ip string, suffix string, proto string) bool {

	url := "https://" + ip + "/" + suffix
	m := new(dns.Msg)
	fqdn := dns.Fqdn(QueryDomain)
	m.SetQuestion(fqdn, dns.TypeA)

	data, err := m.Pack()
	if err != nil {
		fmt.Println(err)
	}
	PostBody := bytes.NewReader(data)
	req, err := http.NewRequest(http.MethodPost, url, PostBody)
	if err != nil {
		return false
	}
	req.Proto = proto
	req.Header.Set("Content-Type", DohDnsType)
	//req.Header.Set("Accept", DohDnsType)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MaxVersion: 0,
		},
	}

	Client := http.Client{
		Timeout: 5 * time.Second,
		Transport: transport,
	}
	resp, err := Client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK && resp.Header.Get("Content-Type") == DohDnsType{
		return true
	}else{
		return false
	}
}

func jsonDns(ip string, suffix string, proto string) bool {

	url := "https://" + ip + "/" + suffix + JsonQuery
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	req.Proto = proto
	req.Header.Set("Content-Type", DohJsonType)
	//req.Header.Set("Accept", DohDnsType)
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MaxVersion: 0,
		},
	}

	Client := http.Client{
		Timeout: 5 * time.Second,
		Transport: transport,
	}
	resp, err := Client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK && resp.Header.Get("Content-Type") == DohJsonType{
		return true
	}else{
		return false
	}
}


func DohScan(target *ScanResult, scan_f *os.File){
	target.GetH1 = getDns(target.Ip, target.Suffix, "HTTP/1.1")
	target.GetH2 = getDns(target.Ip, target.Suffix, "HTTP/2.0")
	target.PostH1 = postDns(target.Ip, target.Suffix, "HTTP/1.1")
	target.PostH2 = postDns(target.Ip, target.Suffix, "HTTP/2.0")
	target.JsonH1 = jsonDns(target.Ip, target.Suffix, "HTTP/1.1")
	target.JsonH2 = jsonDns(target.Ip, target.Suffix, "HTTP/2.0")

	if target.GetH1 || target.GetH2 || target.PostH1 || target.PostH2 || target.JsonH1 || target.JsonH2{
		target.ResFlag = true
		scan_f.WriteString(target.Ip + "," + target.Suffix + "," +  strconv.FormatBool(target.ResFlag) + "," +  strconv.FormatBool(target.GetH1) +
			"," +  strconv.FormatBool(target.GetH2) + "," +  strconv.FormatBool(target.PostH1) + "," +  strconv.FormatBool(target.PostH2) + "," +
			strconv.FormatBool(target.JsonH1) + "," +  strconv.FormatBool(target.JsonH2) + "\n")
	}else{
		fmt.Println(target.Ip,target.Suffix)
	}
}

func run(jobs <-chan string, ScanFile string, wg *sync.WaitGroup, limiter *rate.Limiter, ctx context.Context) {
	defer wg.Done()
	//port := 443

	scan_f, err_ := os.Create(ScanFile)
	if err_ != nil {
		fmt.Println(err_.Error())
	}

	var suffixList = [...]string{"dns-query","query","resolve",""}

	for line := range jobs {

		limiter.Wait(ctx)
		for _, suffix := range suffixList {
			target := new(ScanResult)
			target.Ip = line
			target.Suffix = suffix
			DohScan(target, scan_f)

		}

	}

	scan_f.Close()
}

func main() {
	args := os.Args[1:]

	numThreads, _ := strconv.Atoi(args[0]) // the number of threads default: 500
	inputFile := args[1]                   // seed file
	resultpath := args[2]                      // path of the output file

	startTime := time.Now()
	fmt.Println("start scan at:", startTime)
	QPS := 1000                              // 令牌桶算法，往桶里面放令牌的速度，可以理解为每秒的发包数量，根据带宽大小设定
	jobs := make(chan string)
	var wg sync.WaitGroup
	limiter := rate.NewLimiter(rate.Limit(QPS), 1)
	ctx := context.Background()

	for w := 0; w < numThreads; w++ {
		go func(wgScoped *sync.WaitGroup, limiterScoped *rate.Limiter, i int, ctxScoped context.Context) {
			wgScoped.Add(1)

			scanFile := resultpath + "doh-" + strconv.Itoa(i) + ".txt"

			run(jobs, scanFile, wgScoped, limiterScoped, ctxScoped)
		}(&wg, limiter, w, ctx)
	}

	inputf, err := os.Open(inputFile)
	if err != nil {
		err.Error()
	}
	scanner := bufio.NewScanner(inputf)

	for scanner.Scan() {
		jobs <- scanner.Text()
	}
	close(jobs)
	wg.Wait()

	inputf.Close()

	endTime := time.Now()
	fmt.Println("end scan at:", endTime)
	fmt.Println("duration:", time.Since(startTime).String())

}
