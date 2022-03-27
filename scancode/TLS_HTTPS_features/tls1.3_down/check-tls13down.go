package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"golang.org/x/net/context"
	"golang.org/x/time/rate"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type TLSResult struct {
	Domain    		string 		`json:"domain"`
	Ip        		string 		`json:"ip"`
	TLS13Down12		bool		`json:"tls13_down_12"`
	TLS13Down11		bool		`json:"tls13_down_11"`
	TLS13Down10		bool		`json:"tls13_down_10"`
}

func Scan(tlstarget *TLSResult, port string, tlsf *os.File,){
	ip := tlstarget.Ip
	domain := tlstarget.Domain
	tlstarget.TLS13Down12, _ = tls.Checktls13downgrade(ip, domain, port, tls.VersionTLS12)
	tlstarget.TLS13Down11, _ = tls.Checktls13downgrade(ip, domain, port, tls.VersionTLS11)
	tlstarget.TLS13Down10, _ = tls.Checktls13downgrade(ip, domain, port, tls.VersionTLS10)

	tlsresult, _ := json.Marshal(tlstarget)
	tlsf.Write(tlsresult)
	tlsf.WriteString("\n")

}

// 读取通道，准备扫描
func start(jobs <-chan string, ResultFile string, port string, wg *sync.WaitGroup, limiter *rate.Limiter, ctx context.Context) {
	defer wg.Done()

	// 创建输出文件
	out_f, err_ := os.Create(ResultFile)
	if err_ != nil {
		println(err_.Error())
	}

	// 读取通道
	for line := range jobs {
		limiter.Wait(ctx)

		split := strings.Split(line, ",")

		tlstarget := new(TLSResult)

		tlstarget.Ip = split[0]
		tlstarget.Domain = split[1]

		// 开始扫描
		Scan(tlstarget, port, out_f)
	}
	// 关闭输出文件
	out_f.Close()
}



func main() {
	args := os.Args[1:]
	numThreads, _ := strconv.Atoi(args[0]) // 进程数量
	inputFile := args[1]                   // 输入文件
	resultpath := args[2]                  // 输出文件夹路径
	port := args[3]

	startTime := time.Now()
	fmt.Println("start scan at:", startTime)

	QPS := 400                             // 令牌桶算法，往桶里面放令牌的速度，可以理解为每秒的发包数量，根据带宽大小设定
	jobs := make(chan string)
	var wg sync.WaitGroup
	limiter := rate.NewLimiter(rate.Limit(QPS), 1)
	ctx := context.Background()
	// 创建进程
	for w := 0; w < numThreads; w++ {
		go func(wgScoped *sync.WaitGroup, limiterScoped *rate.Limiter, i int, ctxScoped context.Context) {
			wgScoped.Add(1)
			// 四个输出文件
			ResultFile := resultpath + "down-" + strconv.Itoa(i) + ".txt"

			// 开始扫描
			start(jobs, ResultFile, port, wgScoped, limiterScoped, ctxScoped)
		}(&wg, limiter, w, ctx)
	}
	// 读取输入文件
	inputf, err := os.Open(inputFile)
	if err != nil {
		err.Error()
	}
	scanner := bufio.NewScanner(inputf)
	// 将输入写入通道
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
