package main

import (
	"bytes"
	//"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	//"strings"
	dist "github.com/agext/levenshtein"
	ct "github.com/google/certificate-transparency-go"
	//ctTls "github.com/google/certificate-transparency-go/tls"
	ctX509 "github.com/google/certificate-transparency-go/x509"
	"io"
	"os"
	"time"
	"sort"
	"strconv"
	"encoding/csv"

)

type CertData struct {
	LeafInput string `json:"leaf_input"`
	ExtraData string `json:"extra_data"`
}

type CertPair struct {
	first *ctX509.Certificate
	second *ctX509.Certificate
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
type LogData struct { // <<<===== Используем другой тип.
	Entries []ct.LeafEntry // <<<===== Это тип из библиотеки.
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
	return int64(sth.TreeSize)/100
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

func getAndParseCerts(startIndex int64, endIndex int64, masCerts *[]*ctX509.Certificate, url string) {
	var i int64
	certificates := make(map[string]*ctX509.Certificate)
	for i = startIndex; i < endIndex; i += 20 {
		certs := getCerts(i, i+19, url)
		for _, certificate := range certs.Entries {
			parsedEntry, e := ct.LogEntryFromLeaf(1001, &certificate)
			if e != nil {
				fmt.Printf("ERROR (LogEntryFromLeaf()) : %s\n", e.Error())
				return
			}
			
			//var parsedEntryDataType string
			if parsedEntry.X509Cert != nil {
				//parsedEntryDataType = "Cert"
				signature := base64.StdEncoding.EncodeToString(parsedEntry.X509Cert.Signature)
				_, ok := certificates[signature]
				if !ok {
					*masCerts = append(*masCerts, parsedEntry.X509Cert)
				}
			} else {
				if parsedEntry.Precert != nil {
					//parsedEntryDataType = "Precert"
					cert, _ := ctX509.ParseCertificate(parsedEntry.Precert.Submitted.Data);
					signature := base64.StdEncoding.EncodeToString(cert.Signature)
					_, ok := certificates[signature]
					if !ok {
						*masCerts = append(*masCerts, cert)
					}
				} else {
					fmt.Printf("Incompatible values!\n")
				}
			}
		}
	}
}

func collectLogs() []*ctX509.Certificate {
	var masCerts []*ctX509.Certificate
	for i := 0; i < len(logs); i++ {
		size := getLenOfLog(logs[i])
		getAndParseCerts(0, size, &masCerts, logs[i])
	}
	return masCerts
}

func ValidPeriods(mas []*ctX509.Certificate) map[*ctX509.Certificate]int {
	periods := make(map[int][]*ctX509.Certificate)
	certificatesWithPeriod := make(map[*ctX509.Certificate]int)
	for _, cert := range mas {
		end := cert.NotAfter
		start := cert.NotBefore
		interval := end.Sub(start)
		hours := int(interval.Hours())
		periods[hours] = append(periods[hours], cert)
		certificatesWithPeriod[cert] = hours
	}
	for period, masOfCerts := range periods {
		fmt.Println("Period:", period, "h (", int(period/24), "days )", ", amount:", len(masOfCerts))
		/*for _, cert := range masOfCerts {
			for _, domain := range cert.DNSNames {
					fmt.Println(domain)
			}
		}*/
		fmt.Println("-------------------------")
	}
	fmt.Println("========================")
	return certificatesWithPeriod
}

func CAs(mas []*ctX509.Certificate) {
	CA := make(map[string][]*ctX509.Certificate)
	for _, cert := range mas {
		issuer := cert.Issuer.CommonName
		CA[issuer] = append(CA[issuer], cert)
	}
	for issuer, masOfCerts := range CA {
		fmt.Println("CA:", issuer, "amount:", len(masOfCerts))
		/*for _, cert := range masOfCerts {
			for _, domain := range cert.DNSNames {
					fmt.Println(domain)
			}
		}*/
		fmt.Println("-------------------------")
	}
	fmt.Println("========================")
}

func ValidCheck(mas []*ctX509.Certificate) (map[*ctX509.Certificate]bool, map[*ctX509.Certificate]bool) {
	var ValidCerts []*ctX509.Certificate
	var InvalidCerts []*ctX509.Certificate
	var ValidWithSignCerts []*ctX509.Certificate
	var InvalidWithSignCerts []*ctX509.Certificate
	TimeValid := make(map[*ctX509.Certificate]bool)
	Verified := make(map[*ctX509.Certificate]bool)
	for _, cert := range mas {
		time := time.Now()
		end := cert.NotAfter
		isValid := end.After(time)
		if isValid {
			ValidCerts = append(ValidCerts, cert)
			TimeValid[cert] = true
		} else {
			InvalidCerts = append(InvalidCerts, cert)
			TimeValid[cert] = false
		}
	}
	file, err := os.Open("vened/middle.txt")
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()
	dataMiddle := make([]byte, 10000)
	for {
		_, err := file.Read(dataMiddle)
		if err == io.EOF { // если конец файла
			break // выходим из цикла
		}
	}
	file, err = os.Open("vened/root.txt")
	if err != nil {
		fmt.Println(err)
	}
	defer file.Close()
	dataRoot := make([]byte, 10000)
	for {
		_, err := file.Read(dataRoot)
		if err == io.EOF { // если конец файла
			break // выходим из цикла
		}
	}
	//fmt.Println(dataRoot)
	roots := ctX509.NewCertPool()
	intermediates := ctX509.NewCertPool()
	ok := roots.AppendCertsFromPEM(dataRoot)
	if !ok {
		fmt.Println("failed to parse root certificate")
	}
	ok = intermediates.AppendCertsFromPEM(dataMiddle)
	if !ok {
		fmt.Println("failed to parse intermediate certificate")
	}
	for _, cert := range ValidCerts {
		opts := ctX509.VerifyOptions{
			//DNSName: cert.DNSNames[0],
			Roots:             roots,
			Intermediates:     intermediates,
			DisableCriticalExtensionChecks: true,
			
		}
		_, err := cert.Verify(opts)
		if err == nil {
			ValidWithSignCerts = append(ValidWithSignCerts, cert)
			Verified[cert] = true
		} else {
			fmt.Println(err)
			Verified[cert] = false
		}
	}
	for _, cert := range InvalidCerts {
		opts := ctX509.VerifyOptions{
			//DNSName: cert.DNSNames[0],
			Roots:             roots,
			Intermediates:     intermediates,
			DisableCriticalExtensionChecks: true,
			DisableTimeChecks: true,
		}
		_, err := cert.Verify(opts)
		if err == nil {
			ValidWithSignCerts = append(InvalidWithSignCerts, cert)
			Verified[cert] = true
		} else {
			fmt.Println(err)
			Verified[cert] = false
		}
	}
	fmt.Println("VALID:", len(ValidCerts), len(ValidWithSignCerts))
	/*for _, cert := range ValidWithSignCerts {
		for _, domain := range cert.DNSNames {
			fmt.Println(domain)
		}
	}*/
	fmt.Println("-------------------------")
	fmt.Println("INVALID:", len(InvalidCerts), len(InvalidWithSignCerts))
	/*for _, cert := range InvalidCerts {
		for _, domain := range cert.DNSNames {
			fmt.Println(domain)
		}
	}*/
	fmt.Println("========================")
	return TimeValid, Verified

}
func SerialNumFormat(mas []*ctX509.Certificate) map[*ctX509.Certificate]bool {
	var CorrectFormat []*ctX509.Certificate
	mapFormat := make(map[*ctX509.Certificate]bool)
	for _, cert := range mas {
		bits := cert.SerialNumber.BitLen()
		if (bits >= 64) && (cert.SerialNumber.Bit(bits) == 0) {
			CorrectFormat = append(CorrectFormat, cert)
			mapFormat[cert] = true
		} else {
			mapFormat[cert] = false
		}
	}
	fmt.Println("Correct Format:", len(CorrectFormat))
	fmt.Println("========================")
	return mapFormat
}

func NearSerialNums(mas []*ctX509.Certificate) {
	distances := make(map[CertPair]int)
	for i, cert1 := range mas {
		for j, cert2 := range mas {
			if (i >= j) {
				continue
			}
			if (base64.StdEncoding.EncodeToString(cert1.Signature) == base64.StdEncoding.EncodeToString(cert2.Signature)) {
				continue
			}
			dif := dist.Distance(cert1.SerialNumber.String(), cert2.SerialNumber.String(), nil)
			var pair CertPair
			pair.first = cert1
			pair.second = cert2
			distances[pair] = dif
			//fmt.Println(dif, "\n", cert1.SerialNumber, cert1.Subject, cert2.SerialNumber, cert2.Subject)
		}
	}
}
func NearCertsNearNums(mas []*ctX509.Certificate) {
	sort.Sort(Certs(mas))
	distances := make(map[CertPair]int)
	for i := 0; i < len(mas)-1; i++ {
		dif := dist.Distance(mas[i].SerialNumber.String(), mas[i+1].SerialNumber.String(), nil)
		var pair CertPair
		pair.first = mas[i]
		pair.second = mas[i+1]
		distances[pair] = dif
		fmt.Println(dif, "\n", mas[i].SerialNumber, mas[i].NotBefore, mas[i].Subject, mas[i+1].SerialNumber, mas[i+1].NotBefore, mas[i+1].Subject)	
	}
}

func csvWriter (data [][]string, name string) {
	file, err := os.Create(name + ".csv")
 	if err != nil {
  		fmt.Println("Ошибка при создании файла:", err)
  		return
 	}
 	defer file.Close()
 	writer := csv.NewWriter(file)
 	defer writer.Flush()
 	for _, record := range data {
  		if err := writer.Write(record); err != nil {
   			fmt.Println("Ошибка при записи данных:", err)
   			return
  		}
	}
 	fmt.Println("CSV файл " + name + " успешно создан.")
}
func dataAboutCerts (mas []*ctX509.Certificate, periods map[*ctX509.Certificate]int, format map[*ctX509.Certificate]bool, validTime map[*ctX509.Certificate]bool, verified map[*ctX509.Certificate]bool) [][]string {
	data := [][]string{
  		{"CommonName", "CA", "SerialNumber", "HourPeriod", "CorrectFormatSerialNum", "IsTimeValid", "IsVerified"},
  	}
	for _, cert := range mas {
		str := []string{cert.Subject.CommonName, cert.Issuer.CommonName, cert.SerialNumber.String(), strconv.Itoa(periods[cert]), strconv.FormatBool(format[cert]), strconv.FormatBool(validTime[cert]), strconv.FormatBool(verified[cert])}
		data = append(data, str)
	}
	return data
}
func dataAboutSimilarity(mas map[CertPair]int) [][]string{
	data := [][]string{
  		{"Cert1", "Cert2", "Difference"},
  	}
  	for pair, difference := range mas {
		str := []string{pair.first.Subject.CommonName, pair.second.Subject.CommonName, strconv.Itoa(difference)}
		data = append(data, str)
	}
	return data
}

func main() {
	mas := collectLogs()
	periods := ValidPeriods(mas)
	timeValid, verified := ValidCheck(mas)
	CAs(mas)
	correct := SerialNumFormat(mas)
	data := dataAboutCerts(mas, periods, correct, timeValid, verified)
	csvWriter(data, "certificates")
	//NearSerialNums(mas)
	//NearCertsNearNums(mas)
}
