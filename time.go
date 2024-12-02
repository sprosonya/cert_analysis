package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
	ct "github.com/google/certificate-transparency-go"
	ctX509 "github.com/google/certificate-transparency-go/x509"	
)
type CertData struct {
	LeafInput string `json:"leaf_input"`
	ExtraData string `json:"extra_data"`
}
type CertPair struct {
	first *ctX509.Certificate
	second *ctX509.Certificate
	dif int
}

type Certs []*ctX509.Certificate
func (e Certs) Len() int {
    return len(e)
}
func (e Certs) Less(i, j int) bool {
    return e[i].NotBefore.Before(e[j].NotBefore)
}
func (e Certs) Swap(i, j int) {
    e[i], e[j] = e[j], e[i]
}

var logs = [9]string{
	"https://ct-agate.yandex.net/2025/",
	"https://ctlog2025.mail.ru/nca2025/",
	"https://25.ctlog.digital.gov.ru/2025/",
	"https://24.ctlog.digital.gov.ru/2024/",
	"https://ctlog2024.mail.ru/nca2024/",
	"https://ctlog2023.mail.ru/nca2023/",
	"https://ct-agate.yandex.net/2024/",
	"https://ct-agate.yandex.net/2023/",
	"https://ct-agate.yandex.net/2022/",
}

type CertLog struct {
	Entries []CertData
}

type LogData struct {
	Entries []ct.LeafEntry
}

func getLenOfLog(url string) int64 {
	var sth ct.SignedTreeHead
	urlAPI := fmt.Sprintf(url + "ct/v1/get-sth")
	resp, err := http.Get(urlAPI)
	if err != nil {
		fmt.Println(err)
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	err = json.Unmarshal(buf.Bytes(), &sth)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(int64(sth.TreeSize))
	return int64(sth.TreeSize)
}

func getCerts(start int64, end int64, url string) LogData {
	urlAPI := fmt.Sprintf(url+"ct/v1/get-entries?start=%d&end=%d", start, end)
	resp, err := http.Get(urlAPI)
	if err != nil {
		fmt.Println(err)
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(resp.Body)
	var results LogData
	err = json.Unmarshal(buf.Bytes(), &results)
	if err != nil {
		fmt.Println(err)
	}
	return results
}

func getAndParseCerts(startIndex int64, endIndex int64, masCerts *[]*ctX509.Certificate, CertPrecert map[*ctX509.Certificate]bool, hash_certs map[string]bool, url string) {
	var i int64
	for i = startIndex; i < endIndex; i += 50 {
		certs := getCerts(i, i+49, url)
		for _, certificate := range certs.Entries {
			parsedEntry, e := ct.LogEntryFromLeaf(1, &certificate)
			if e != nil {
				fmt.Printf(e.Error())
				return
			}
			fmt.Println(time.UnixMilli(int64(parsedEntry.Leaf.TimestampedEntry.Timestamp)))
			var cert *ctX509.Certificate
			var err error
			if parsedEntry.X509Cert != nil {
				cert = parsedEntry.X509Cert
				CertPrecert[cert] = true
			} else if parsedEntry.Precert != nil {
				cert, err = ctX509.ParseCertificate(parsedEntry.Precert.Submitted.Data)
				CertPrecert[cert] = false
				if err != nil {
					log.Println("Error parsing precert:", err)
				}
			} else {
				fmt.Println("Incompatible values!")
				cert = nil
			}
			if cert != nil {
				hash := sha256.New()
				hash.Write(cert.Raw)
				hash_string := string(hash.Sum(nil))
				if exists := hash_certs[hash_string]; !exists {
					*masCerts = append(*masCerts, cert)
					hash_certs[hash_string] = true
				}
			}
		}
	}
	fmt.Println(len(*masCerts), "OOOOO")
}
func collectLogs() ([]*ctX509.Certificate, map[*ctX509.Certificate]bool) {
	var masCerts []*ctX509.Certificate
	var hash_certs map[string]bool = make(map[string]bool)
	var CertPrecert map[*ctX509.Certificate]bool = make(map[*ctX509.Certificate]bool)
	for i := 0; i < len(logs); i++ {
		size := getLenOfLog(logs[i])
		getAndParseCerts(0, size, &masCerts, CertPrecert, hash_certs, logs[i])
	}
	return masCerts, CertPrecert
}
func main() {
	_, _ = collectLogs()
}