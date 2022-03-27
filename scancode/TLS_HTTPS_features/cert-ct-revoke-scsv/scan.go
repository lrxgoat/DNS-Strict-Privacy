/*
	代码对域名的TLS/HTTPS安全进行测量，包括TLS版本、证书、CT、证书撤销以及TLS降级攻击。
	在go.mod的添加：
		replace github.com/Sirupsen/logrus v1.8.1 => github.com/sirupsen/logrus v1.8.1

	输入为(ip,domain)格式的文件, 参数依次为进程数量, 输入文件, 输出文件夹。
	ex: go run scan.go 100 ./input.txt ./result/
	输出为四个json文件，分别为TLSResult, CertResult, CTResult, RevokeResult 结构体
*/


package main

import (
	"bufio"
	"bytes"
	"crypto"
	_"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/certifi/gocertifi"
	"github.com/tumi8/tls"
	"github.com/zzylydx/Zgoscanner/scanner"
	sct "github.com/zzylydx/Zsct"
	zocsp "github.com/zzylydx/zcrypto/x509/revocation/ocsp"
	"golang.org/x/crypto/ocsp"
	"golang.org/x/net/context"
	"golang.org/x/time/rate"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var cipherSuites map[uint16]string	// 保存TLS版本

var scsvCiphers = []uint16{
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,   // for TLS < 1.2
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, // for TLS < 1.2
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,   // for TLS < 1.2
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, // for TLS < 1.2
	tls.TLS_FALLBACK_SCSV,	// SCSV 密码套件
}

type TLSResult struct {
	Domain    		string 		`json:"domain"`
	Ip        		string 		`json:"ip"`
	TlsVersion  	string		`json:"tlsVersion"`
	SCSV			bool		`json:"scsv"`
	ConnError 		string 		`json:"connError"`
}

type CertResult struct{
	Domain    		string 		`json:"domain"`
	Ip        		string 		`json:"ip"`
	RawCertChain	string		`json:"raw_cert_chain"`	// 原始证书链
	CertLevel		string		`json:"cert_level"`	// DV,OV,EV
	CertValid		bool		`json:"certValid"`
	CAName          []string	`json:"caName"`
	TimeValid		bool 		`json:"time_valid"`	// 证书是否在有效期
	CertLifetime	float64		 `json:"cert_lifetime"`	// 证书生命周期
	CertError		string		`json:"cert_error"`
	ConnError 		string 		`json:"connError"`
}

type CTResult struct {
	Domain    		string 		`json:"domain"`
	Ip        		string 		`json:"ip"`
	// TLS传递方式
	TlsHave  		bool 		`json:"tlsHave"`
	TlsValid		string		`json:"sct_tls_valid"`	// 保存每一个sct验证结果
	TlsLog			string		`json:"tls_log"`	// 保存每一个sct的log
	// Cert传递方式
	CertHave		bool 		`json:"certHave"`
	CertValid		string		`json:"cert_valid"`
	CertLog			string		`json:"cert_log"`
	// OCSP传递方式
	OcspHave 		bool 		`json:"ocspHave"`
	OCSPValid		string		`json:"ocsp_valid"`
	OCSPLog			string		`json:"ocsp_log"`

	FlagValid		bool 		`json:"flagValid"`   	// 只要有一个sct验证成功，即为true
	ConnError 		string 		`json:"connError"`
}


type RevokeResult struct {
	Domain    		string 		`json:"domain"`
	Ip        		string 		`json:"ip"`
	// 传递方式
	CRL 			bool		`json:"crLs"`
	CRLServer		[]string	`json:"crl_server"`
	OCSP 			bool		`json:"ocsp"`
	OCSPServer		[]string	`json:"ocspServer"`
	OCSPStapling	bool		`json:"ocspStapling"`
	OCSPMustStaple	bool		`json:"ocspMustStaple"`
	RespectMS		bool		`json:"respect_ms"`	// 在证书中包含OCSP Must-Staple时，如果TLS中有OCSP响应则为true
	// 撤销响应，依次使用OCSPStapling, OCSP, CRL进行请求
	ResponseFlag  bool   `json:"response_flag"` // 收到撤销响应，则为true
	CrlCertStatus string `json:"crl_cert_status"`   // 证书状态
	CrlResponseSig bool `json:"crl_response_sig"`   // 响应签名
	OCSPCertStatus string `json:"ocsp_cert_status"`
	OCSPResponseSig bool `json:"ocsp_response_sig"`
	OCSPStaplingCertStatus string `json:"ocsp_stapling_cert_status"`
	OCSPStaplingResponseSig bool  `json:"ocsp_stapling_response_sig"`
	ConnError     string `json:"connError"`
}

// 检查OCSP响应
func checkOCSP(res *ocsp.Response, leafcert *x509.Certificate)(string, bool){
	var status string
	var sigflag bool
	switch res.Status {
	case ocsp.Good:
		status = "Good"
	case ocsp.Revoked:
		status = "Revoked"
	case ocsp.ServerFailed:
		status = "ServerFailed"
	case ocsp.Unknown:
		status = "Unknown"
	default:
		status = "Error"
	}
	if res != nil && leafcert != nil{
		if err := res.CheckSignatureFrom(leafcert); err == nil {
			sigflag = true
		} else {
			sigflag = false
		}
	}

	return status, sigflag
}

// 获取url的证书，用于生成OCSP请求
func fetchRemote(url string) (*x509.Certificate, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	in, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	return parseCert(in)
}

// 将byte数组解析为证书
func parseCert(in []byte) (*x509.Certificate, error) {
	p, _ := pem.Decode(in)
	if p != nil {
		if p.Type != "CERTIFICATE" {
			return nil, errors.New("invalid certificate")
		}
		in = p.Bytes
	}

	return x509.ParseCertificate(in)
}


// 验证域名的证书链，参考 https://golang.org/src/crypto/x509/verify.go 以及 https://gist.github.com/devtdeng/4f6adcb5a306f2ae035a2e7d9f724d17
func checkCertsChain(state *tls.ConnectionState,domain string) (bool,string) {
	// get Mozilla Root CA Certificates
	roots, _ := gocertifi.CACerts()
	// certNumber
	certNum := len(state.PeerCertificates)
	// 分情况
	if certNum == 0 {
		return false,"certNum is 0"
	}
	if certNum == 1{
		// leafcert
		leafCert := state.PeerCertificates[0]
		// config
		opts := x509.VerifyOptions{
			DNSName: domain,
			Roots:   roots,
		}
		if _, err := leafCert.Verify(opts); err != nil {
			return false,err.Error()
		}
	}else{
		// leafcert
		leafCert := state.PeerCertificates[0]
		// inter certs
		inter := x509.NewCertPool()
		for _, cert := range state.PeerCertificates[1:]{
			inter.AddCert(cert)
		}
		// config
		opts := x509.VerifyOptions{
			DNSName: domain,
			Roots:   roots,
			Intermediates: inter,

		}
		if _, err := leafCert.Verify(opts); err != nil {
			return false,err.Error()
		}
	}

	return true,""
}

// 进行TLS连接
func scanTLS(conn *net.Conn, serverName string, timeout time.Duration, maxVersion uint16, ciphers []uint16) (*tls.Conn, error) {

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		// Use SNI if domain name is available
		ServerName: serverName,
		MaxVersion: maxVersion,
	}
	if ciphers != nil {
		tlsConfig.CipherSuites = ciphers
	}

	tlsConn := tls.Client(*conn, tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(timeout))
	err := tlsConn.Handshake()

	return tlsConn, err
}

// 重新建立TCP连接
func reconnect(conn *net.Conn, timeout time.Duration) (*net.Conn, error) {
	localAddr, _, _ := net.SplitHostPort((*conn).LocalAddr().String()) // 本地地址
	ip := (*conn).RemoteAddr().String() // 远程地址
	// Close previous connection
	(*conn).Close()

	dialer := net.Dialer{Timeout: timeout, LocalAddr: &net.TCPAddr{IP: net.ParseIP(localAddr)}}

	var newConn net.Conn
	newConn, err := dialer.Dial("tcp", ip)

	if err != nil{
		return &newConn, err
	}

	return &newConn, nil
}

// Scan 主函数, 对TLS/HTTPS安全进行测量
func Scan(tlstarget *TLSResult, certtarget *CertResult, cttarget *CTResult, revoketarget *RevokeResult, tlsf *os.File, certf *os.File, ctf *os.File, revokef *os.File, port string) (bool, string) {
	var buf bytes.Buffer
	domain := strings.TrimRight(tlstarget.Domain, ".")
	buf.WriteString(tlstarget.Ip)
	buf.WriteString(":")
	buf.WriteString(port)
	fullAddr := buf.String()


	// 建立tcp连接
	timeout := 15 * time.Second
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", fullAddr)
	if err != nil {
		return false, err.Error()
	}
	conn.SetDeadline(time.Now().Add(timeout))

	// 建立TLS连接
	tlsConn, err := scanTLS(&conn, domain, timeout, 0,nil)
	if err != nil {
		return false, err.Error()
	}
	state := tlsConn.ConnectionState()

	// TLS版本
	var protocol string
	var ok bool
	if protocol, ok = cipherSuites[state.Version]; !ok {
		protocol = "not_set"
	}
	tlstarget.TlsVersion = protocol

	// 分析证书
	// 获取证书链
	certchain := ""
	for _, cert := range state.PeerCertificates {
		var block = &pem.Block{
			Type: "CERTIFICATE",
			Bytes: cert.Raw,
		}

		aa := pem.EncodeToMemory(block)
		enc := base64.StdEncoding.EncodeToString(aa)
		certchain = certchain + "," + enc	// 分隔符 ","
	}
	certtarget.RawCertChain = strings.TrimLeft(certchain, ",")

	// 获取证书等级
	chain, err := sct.BuildCertificateChain(state.PeerCertificates)
	if err != nil {
		return false, err.Error()
	}
	if len(chain) != 0{
		certtarget.CertLevel = sct.ValidationLevel(chain[0])
	}

	leafcert := state.PeerCertificates[0]

	// 检查证书有效性
	certtarget.CertValid, certtarget.CertError = checkCertsChain(&state,domain)
	// CA
	certtarget.CAName = leafcert.Issuer.Organization
	// 生命周期，输出天数，float类型
	certtarget.CertLifetime = leafcert.NotAfter.Sub(leafcert.NotBefore).Hours()/24
	// 证书时间有效性
	now := time.Now()
	certtarget.TimeValid = true
	if now.Before(leafcert.NotBefore) {
		certtarget.TimeValid = false
	}else if now.After(leafcert.NotAfter) {
		certtarget.TimeValid = false
	}

	// 分析CT
	var flagValid string //暂时保存每个sct验证结果

	// sct TLS
	checker := sct.GetDefaultChecker()
	sctTLS := state.SignedCertificateTimestamps
	if len(sctTLS) != 0{
		var checkTLSFlag string	  // verify results
		var logDescription string // log Description

		for _, sctTLS := range sctTLS {
			ld, checkTLS := checker.VerifyTLSSCTs(sctTLS, chain)
			checkTLSFlag = checkTLSFlag  + strconv.FormatBool(checkTLS) + "#||#"
			logDescription = logDescription + ld + "#||#"
		}

		cttarget.TlsValid = strings.TrimRight(checkTLSFlag,"#||#")
		cttarget.TlsLog = strings.TrimRight(logDescription, "#||#")
		cttarget.TlsHave = true
		flagValid = flagValid + checkTLSFlag      // 将所有sct的验证结果串起来，后面判断如果包含true，那么该域名的sct是有效的
	}else {
		cttarget.TlsHave = false
	}

	// sct cert
	if len(chain[0].SCTList.SCTList) != 0 {
		var checkCertFlag string
		var logDescription string

		for _, sctCert := range chain[0].SCTList.SCTList {
			ld, checkCert := checker.VerifyCertSCTs(&sctCert, chain)
			checkCertFlag = checkCertFlag + strconv.FormatBool(checkCert) + "#||#"
			logDescription = logDescription + ld + "#||#"
		}

		cttarget.CertValid = strings.TrimRight(checkCertFlag, "#||#")
		cttarget.CertLog = strings.TrimRight(logDescription, "#||#")
		flagValid = flagValid + checkCertFlag
		cttarget.CertHave = true
	}else {
		cttarget.CertHave = false
	}

	// sct ocsp
	if len(state.OCSPResponse) != 0{
		// 获取在包含在TLS握手中的OCSP响应中的sct
		ocspEncode := base64.StdEncoding.EncodeToString(state.OCSPResponse)
		ocspResponse, err := zocsp.ConvertResponse(ocspEncode)
		if err != nil{
			cttarget.OcspHave = false
		}else{
			var sctsOcsp [][]byte
			sctsOcsp, err = zocsp.ParseSCTListFromOcspResponseByte(ocspResponse)
			if err != nil{
				cttarget.OcspHave = false
			}else{
				if sctsOcsp != nil {
					var checkOcspFlag string
					var sctsOcspData string
					var logDescription string

					for _, sctOcsp := range sctsOcsp {
						ld, checkOcsp := checker.VerifyOcspSCTs(sctOcsp, chain)
						enc := base64.StdEncoding.EncodeToString(sctOcsp)
						checkOcspFlag = checkOcspFlag + strconv.FormatBool(checkOcsp) + "#||#"
						sctsOcspData = sctsOcspData + enc + "#||#"
						logDescription = logDescription + ld + "#||#"
					}

					cttarget.OCSPValid = strings.TrimRight(checkOcspFlag, "#||#")
					cttarget.OCSPLog = strings.TrimRight(logDescription, "#||#")
					flagValid = flagValid + checkOcspFlag
					cttarget.OcspHave = true
				}else {
					cttarget.OcspHave = false
				}

			}
		}



	}

	// 检查是否有一个sct有效
	if strings.Contains(flagValid, "true") {
		cttarget.FlagValid = true
	}else {
		cttarget.FlagValid = false
	}

	// 证书撤销

	// 撤销方式
	// CRL
	if len(leafcert.CRLDistributionPoints) > 0 {
		revoketarget.CRL = true
		revoketarget.CRLServer = leafcert.CRLDistributionPoints
	} else {
		revoketarget.CRL = false
	}

	// OCSP
	if len(leafcert.IssuingCertificateURL) > 0 {
		revoketarget.OCSPServer = state.PeerCertificates[0].OCSPServer
		revoketarget.OCSP = true
	} else {
		revoketarget.OCSP = false
	}

	// OCSP Stapling
	if len(state.OCSPResponse) > 0 {
		revoketarget.OCSPStapling = true
	} else {
		revoketarget.OCSPStapling = false
	}

	// OCSP must-staple
	// Must-Staple is 1.3.6.1.5.5.7.1.24
	var ocspMustStapleExtOid = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}

	for _,ext := range state.PeerCertificates[0].Extensions {
		if ext.Id.Equal(ocspMustStapleExtOid){
			revoketarget.OCSPMustStaple = true
			if revoketarget.OCSPStapling == true{
				revoketarget.RespectMS = true
			}
			break
		}
	}

	// 撤销响应，检测顺序为OCSPStapling->OCSP->CRL
	var issuercert *x509.Certificate
	// 获取CA提供的URL的证书
	for _, issuingCert := range leafcert.IssuingCertificateURL {
		issuercert, err = fetchRemote(issuingCert)
		if err != nil {
			continue
		}
		break
	}

	// OCSPStapling
	if revoketarget.OCSPStapling == true {
		ocspStaplingRes, err := ocsp.ParseResponse(state.OCSPResponse, issuercert)
		if err != nil {
			revoketarget.ResponseFlag = false
		} else {
			status, sigflag := checkOCSP(ocspStaplingRes, issuercert)
			revoketarget.ResponseFlag = true
			revoketarget.OCSPStaplingCertStatus = status
			revoketarget.OCSPStaplingResponseSig = sigflag
		}
	}

	// OCSP
	if revoketarget.OCSP == true {
		ocspURLs := leafcert.OCSPServer
		// 构建OCSP响应
		opts := ocsp.RequestOptions{
			Hash: crypto.SHA1,
		}
		if issuercert != nil {
			ocspRequest, err := ocsp.CreateRequest(leafcert, issuercert, &opts)
			if err != nil {
				revoketarget.OCSPCertStatus = "Error"
			} else {
				// 向每一个OCSPServer发出请求
				for _, server := range ocspURLs {
					var resp *http.Response
					// 请求字节数大于256，使用POST
					if len(ocspRequest) > 256 {
						buf := bytes.NewBuffer(ocspRequest)
						resp, err = http.Post(server, "application/ocsp-request", buf)
					} else {
						reqURL := server + "/" + base64.StdEncoding.EncodeToString(ocspRequest)
						resp, err = http.Get(reqURL)
					}

					if err != nil || resp.StatusCode != http.StatusOK {
						revoketarget.OCSPCertStatus = "Error"
						continue
					}
					// 读取OCSP响应
					body, err := ioutil.ReadAll(resp.Body)

					resp.Body.Close()
					var ocspUnauthorised = []byte{0x30, 0x03, 0x0a, 0x01, 0x06}
					var ocspMalformed = []byte{0x30, 0x03, 0x0a, 0x01, 0x01}
					if err != nil || bytes.Equal(body, ocspUnauthorised) || bytes.Equal(body, ocspMalformed) {
						revoketarget.OCSPCertStatus = "Error"
						continue
					}
					// 解析OCSP响应
					ocspResponse, err := ocsp.ParseResponse(body, issuercert)
					if err != nil {
						revoketarget.OCSPCertStatus = "Error"
						continue
					}

					status, sigflag := checkOCSP(ocspResponse, issuercert)
					revoketarget.ResponseFlag = true
					revoketarget.OCSPCertStatus = status
					revoketarget.OCSPResponseSig = sigflag
				}

			}

		} else {
			revoketarget.OCSPCertStatus = "Error"
		}
	}
		// CRL
	if revoketarget.CRL == true {
		CRLServer := leafcert.CRLDistributionPoints
		var crlresp *http.Response
		for _, crlurl := range CRLServer {
			// 发出crl请求
			crlresp, err = http.Get(crlurl)
			if err != nil {
				revoketarget.CrlCertStatus = "Error"
				continue
			}
			// 读取CRL响应
			body, err := ioutil.ReadAll(crlresp.Body)
			if err != nil {
				revoketarget.CrlCertStatus = "Error"
				continue
			}
			crlresp.Body.Close()
			// 解析CRL响应
			crlresponce, err := x509.ParseDERCRL(body)
			if err != nil {
				revoketarget.CrlCertStatus = "Error"
				continue
			}
			revoketarget.ResponseFlag = true

			rawsernum := leafcert.SerialNumber
			crlrevokeflag := false
			// 检测证书是否包含在CRL列表
			for _, signalcrl := range crlresponce.TBSCertList.RevokedCertificates {
				if signalcrl.SerialNumber == rawsernum {
					crlrevokeflag = true
					break
				}
			}

			if crlrevokeflag == true {
				revoketarget.CrlCertStatus = "Revoked"
			} else {
				revoketarget.CrlCertStatus = "Good"
			}

			// 检查CRL响应签名
			if issuercert != nil{
				if errcrl := issuercert.CheckCRLSignature(crlresponce); errcrl == nil {
					revoketarget.CrlResponseSig = true
				} else {
					revoketarget.CrlResponseSig = false
				}
			}

		}
	}

	// TLS1.2 SCSV

	// 重新连接server
	newConn, err := reconnect(&conn, timeout)
	if err != nil {
		return false, err.Error()
	} else {
		// 在client hello中提供SCSV密码套件
		_, err := scanTLS(newConn, domain, timeout, state.Version-1, scsvCiphers)
		if err != nil {
			if strings.Contains(err.Error(), "remote error: tls:") {
				tlstarget.SCSV = true
			}
		} else {
			tlstarget.SCSV = false
		}
	}
	(*newConn).Close()

	// TLS1.3 降级攻击保护

	//tlstarget.TLS13Down12, _ = tls.Checktls13downgrade(tlstarget.Ip, tlstarget.Domain, port, tls.VersionTLS12)
	//tlstarget.TLS13Down11, _ = tls.Checktls13downgrade(tlstarget.Ip, tlstarget.Domain, port, tls.VersionTLS11)
	//tlstarget.TLS13Down10, _ = tls.Checktls13downgrade(tlstarget.Ip, tlstarget.Domain, port, tls.VersionTLS10)


	// 将保存结果的结构体写入文件

	tlsresult, errjson := json.Marshal(tlstarget)
	if errjson != nil {
		return false, errjson.Error()
	}
	tlsf.Write(tlsresult)
	tlsf.WriteString("\n")

	certresult, errjson := json.Marshal(certtarget)
	if errjson != nil {
		return false, errjson.Error()
	}
	certf.Write(certresult)
	certf.WriteString("\n")

	ctresult, errjson := json.Marshal(cttarget)
	if errjson != nil {
		return false, errjson.Error()
	}
	ctf.Write(ctresult)
	ctf.WriteString("\n")

	revokeresult, errjson := json.Marshal(revoketarget)
	if errjson != nil {
		return false, errjson.Error()
	}
	revokef.Write(revokeresult)
	revokef.WriteString("\n")

	return true, ""
}

// 读取通道，准备扫描
func start(jobs <-chan string, TLSFile string,CertFile string, CTFile string, RevokeFile string, wg *sync.WaitGroup, limiter *rate.Limiter, ctx context.Context) {
	defer wg.Done()
	port := 853		// 扫描DOT服务器, 在853端口进行TLS连接

	// 创建输出文件
	tlsf, err_ := os.Create(TLSFile)
	if err_ != nil {
		println(err_.Error())
	}

	certf, err_ := os.Create(CertFile)
	if err_ != nil {
		println(err_.Error())
	}

	ctf, err_ := os.Create(CTFile)
	if err_ != nil {
		println(err_.Error())
	}

	revokef, err_ := os.Create(RevokeFile)
	if err_ != nil {
		println(err_.Error())
	}
	// 读取通道
	for line := range jobs {
		limiter.Wait(ctx)
		// 创建结构体
		tlstarget := new(TLSResult)
		certtarget := new(CertResult)
		cttarget := new(CTResult)
		revoketarget := new(RevokeResult)
		// 初始化ip,domain
		split := strings.Split(line, ",")

		tlstarget.Ip = split[0]
		tlstarget.Domain = split[1]

		certtarget.Ip = split[0]
		certtarget.Domain = split[1]

		cttarget.Ip = split[0]
		cttarget.Domain = split[1]

		revoketarget.Ip = split[0]
		revoketarget.Domain = split[1]
		// 开始扫描
		success, err := Scan(tlstarget, certtarget, cttarget, revoketarget, tlsf, certf, ctf, revokef, strconv.Itoa(port))
		// 扫描失败
		if !success {
			err = strings.Replace(err, "\n", " ", -1)
			tlstarget.ConnError = err
			certtarget.ConnError = err
			cttarget.ConnError = err
			revoketarget.ConnError = err

			tlserr, errJson := json.Marshal(tlstarget)
			if errJson != nil {
				fmt.Println("Out-errJson:", errJson, tlstarget.Domain)
				continue
			}
			tlsf.Write(tlserr)
			tlsf.WriteString("\n")

			certerr, errJson := json.Marshal(certtarget)
			if errJson != nil {
				fmt.Println("Out-errJson:", errJson, certtarget.Domain)
				continue
			}
			certf.Write(certerr)
			certf.WriteString("\n")

			cterr, errJson := json.Marshal(cttarget)
			if errJson != nil {
				fmt.Println("Out-errJson:", errJson, cttarget.Domain)
				continue
			}
			ctf.Write(cterr)
			ctf.WriteString("\n")

			revokeerr, errJson := json.Marshal(revoketarget)
			if errJson != nil {
				fmt.Println("Out-errJson:", errJson, revoketarget.Domain)
				continue
			}
			revokef.Write(revokeerr)
			revokef.WriteString("\n")
		}
	}
	// 关闭输出文件
	tlsf.Close()
	certf.Close()
	ctf.Close()
	revokef.Close()
}

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	cipherSuites = scanner.ReadCiphersFromAsset()
}

func main() {
	args := os.Args[1:]
	numThreads, _ := strconv.Atoi(args[0]) // 进程数量
	inputFile := args[1]                   // 输入文件
	resultpath := args[2]                  // 输出文件夹路径

	startTime := time.Now()
	fmt.Println("start scan at:", startTime)

	QPS := 400                              // 令牌桶算法，往桶里面放令牌的速度，可以理解为每秒的发包数量，根据带宽大小设定
	jobs := make(chan string)
	var wg sync.WaitGroup
	limiter := rate.NewLimiter(rate.Limit(QPS), 1)
	ctx := context.Background()
	// 创建进程
	for w := 0; w < numThreads; w++ {
		go func(wgScoped *sync.WaitGroup, limiterScoped *rate.Limiter, i int, ctxScoped context.Context) {
			wgScoped.Add(1)
			// 四个输出文件
			TLSFile := resultpath + "tls-" + strconv.Itoa(i) + ".txt"
			CertFile := resultpath + "cert-" + strconv.Itoa(i) + ".txt"
			CTFile := resultpath + "ct-" + strconv.Itoa(i) + ".txt"
			RevokeFile := resultpath + "revoke-" + strconv.Itoa(i) + ".txt"
			// 开始扫描
			start(jobs, TLSFile, CertFile, CTFile, RevokeFile, wgScoped, limiterScoped, ctxScoped)
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
