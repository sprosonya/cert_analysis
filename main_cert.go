package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	dist "github.com/agext/levenshtein"
	ct "github.com/google/certificate-transparency-go"
	ctX509 "github.com/google/certificate-transparency-go/x509"
	"io"
	"os"
	"time"
	"strconv"
	"sort"
	"encoding/csv"
	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/components"
	"github.com/go-echarts/go-echarts/v2/opts"
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
			parsedEntry, e := ct.LogEntryFromLeaf(1001, &certificate)
			if e != nil {
				fmt.Printf("ERROR (LogEntryFromLeaf()) : %s\n", e.Error())
				return
			}
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
	return certificatesWithPeriod
}
func CAs(mas []*ctX509.Certificate) {
	CA := make(map[string][]*ctX509.Certificate)
	for _, cert := range mas {
		issuer := cert.Issuer.CommonName
		CA[issuer] = append(CA[issuer], cert)
	}
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
			Roots:             roots,
			Intermediates:     intermediates,
			DisableCriticalExtensionChecks: true,
			DisableTimeChecks: true,
		}
		_, err := cert.Verify(opts)
		if err == nil {
			InvalidWithSignCerts = append(InvalidWithSignCerts, cert)
			Verified[cert] = true
		} else {
			fmt.Println(err)
			Verified[cert] = false
		}
	}
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
	return mapFormat
}
func NearCertsNearNums(mas []*ctX509.Certificate) []CertPair {
	sort.Sort(Certs(mas))
	var masOfPairs []CertPair
	for i := 0; i < len(mas)-1; i++ {
		dif := dist.Distance(mas[i].SerialNumber.String(), mas[i+1].SerialNumber.String(), nil)
		var pair CertPair
		pair.first = mas[i]
		pair.second = mas[i+1]
		pair.dif = dif
		masOfPairs = append(masOfPairs, pair)
	}
	return masOfPairs
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
func dataAboutCerts (mas []*ctX509.Certificate, periods map[*ctX509.Certificate]int, format map[*ctX509.Certificate]bool, validTime map[*ctX509.Certificate]bool, verified map[*ctX509.Certificate]bool, CertPrecert map[*ctX509.Certificate]bool) [][]string {
	data := [][]string{
  		{"CommonName", "Type", "CA", "SerialNumber", "HourPeriod", "CorrectFormatSerialNum", "IsTimeValid", "IsVerified"},
  	}
	for _, cert := range mas {
		var typeCert string
		if (CertPrecert[cert]==true) {
			typeCert = "certificate"
		} else {
			typeCert = "precertificate"
		}
		str := []string{cert.Subject.CommonName, typeCert, cert.Issuer.CommonName, fmt.Sprintf("%X", cert.SerialNumber), strconv.Itoa(periods[cert]), strconv.FormatBool(format[cert]), strconv.FormatBool(validTime[cert]), strconv.FormatBool(verified[cert])}
		data = append(data, str)
	}
	return data
}
func dataAboutSimilarity(pairs []CertPair, CertPrecert map[*ctX509.Certificate]bool) [][]string{
	data := [][]string{
  		{"Cert1", "SerialNumber1", "Type1", "Cert2", "SerialNumber2", "Type2", "Difference"},
  	}
  	for _, pair := range pairs {
  		var typeCert1, typeCert2 string
		if (CertPrecert[pair.first]==true) {
			typeCert1 = "certificate"
		} else {
			typeCert1 = "precertificate"
		}
		if (CertPrecert[pair.second]==true) {
			typeCert2 = "certificate"
		} else {
			typeCert2 = "precertificate"
		}
		str := []string{pair.first.Subject.CommonName, fmt.Sprintf("%X", pair.first.SerialNumber), typeCert1, pair.second.Subject.CommonName, fmt.Sprintf("%X", pair.second.SerialNumber), typeCert2, strconv.Itoa(pair.dif)}
		data = append(data, str)
	}
	return data
}
func newBar(title string) *charts.Bar {
  bar := charts.NewBar()
  bar.SetGlobalOptions(
    charts.WithTitleOpts(opts.Title{Title: title}),
    charts.WithYAxisOpts(opts.YAxis{Type: "log"}),
    charts.WithInitializationOpts(opts.Initialization{
      Width:  "1200px",
      Height: "600px",
    }),
    charts.WithToolboxOpts(opts.Toolbox{
      Right: "20%",
      Feature: &opts.ToolBoxFeature{
        SaveAsImage: &opts.ToolBoxFeatureSaveAsImage{
          Type:  "jpg",
          Title: "Download .jpg",
        },
        DataView: &opts.ToolBoxFeatureDataView{
          Title: "Data view",
          Lang: []string{"Data view", "Turn off", "Refresh"},
        },
      }},
    ),
  )
  return bar
}
func plotCAs(mas []*ctX509.Certificate) *charts.Bar {
	CA := make(map[string][]*ctX509.Certificate)
	for _, cert := range mas {
		issuer := cert.Issuer.CommonName
		CA[issuer] = append(CA[issuer], cert)
	}
	bar_names := make([]string, 0)
	items := make([]opts.BarData, 0)
	for issuer, certs := range CA {
		bar_names = append(bar_names, issuer)
		items = append(items, opts.BarData{Value: len(certs)})
	}
	bar := newBar("Certificate authorities")
	bar.SetXAxis(bar_names).
		AddSeries("", items)
	return bar
}
func plotNearNums(masOfPairs []CertPair) *charts.Bar {
  bar_names := make([]string, len(masOfPairs))
  items := make([]opts.BarData, 0)
  for _, pair := range masOfPairs {
    bar_names = append(bar_names, pair.second.NotBefore.Format("2006-01-02 15:04:05"))
    items = append(items, opts.BarData{Value: pair.dif})
  }
  bar := newBar("Difference between certificates with near date of release")
  bar.SetXAxis(bar_names).
    AddSeries("", items)
  bar.SetGlobalOptions(
  charts.WithYAxisOpts(opts.YAxis{Type: "value"}),
  charts.WithDataZoomOpts(opts.DataZoom{
   Type:  "slider",
   Start: 0,
   End:   100,
  }),
 )
  return bar
}
func plotPeriods(mas []*ctX509.Certificate) *charts.Bar {
	periods := make(map[int][]*ctX509.Certificate)
	for _, cert := range mas {
		end := cert.NotAfter
		start := cert.NotBefore
		interval := end.Sub(start)
		hours := int(interval.Hours())
		periods[hours] = append(periods[hours], cert)
	}
	bar_names := make([]string, 0)
	items := make([]opts.BarData, 0)
	for period, certs := range periods {
		bar_names = append(bar_names, fmt.Sprintf("%d h (%d days)", period, int(period/24)))
		items = append(items, opts.BarData{Value: len(certs)})
	}
	bar := newBar("Periods")
	bar.SetXAxis(bar_names).
		AddSeries("", items)
	return bar
}
func plot(mas []*ctX509.Certificate, html string) {
	masOfPairs := NearCertsNearNums(mas)
	page := components.NewPage().SetPageTitle("Графики")
	page.InitAssets()
	page.AddCharts(
		plotCAs(mas),
		plotPeriods(mas),
		plotNearNums( masOfPairs),
	)
	f, err := os.Create("plots.html")
	if err != nil {
		panic(err)
	}
	page.Render(io.MultiWriter(f))
	f.WriteString(html)
}
func main() {
	mas, CertPrecert := collectLogs()
	periods := ValidPeriods(mas)
	timeValid, verified := ValidCheck(mas)
	CAs(mas)
	correct := SerialNumFormat(mas)
	dataCert := dataAboutCerts(mas, periods, correct, timeValid, verified, CertPrecert)
	csvWriter(dataCert, "certificates")
	similarityDate:= NearCertsNearNums(mas)
	dataDif := dataAboutSimilarity(similarityDate, CertPrecert)
	csvWriter(dataDif, "similarity")
	plot(mas, "")
}