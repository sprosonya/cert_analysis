package main

import (
	"bytes"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/go-echarts/go-echarts/v2/charts"
	"github.com/go-echarts/go-echarts/v2/components"
	"github.com/go-echarts/go-echarts/v2/opts"
	ct "github.com/google/certificate-transparency-go"
	ctX509 "github.com/google/certificate-transparency-go/x509"
	"io"
	logger "log"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"time"
)

type timeStatisticsLogs struct {
	cert    *ctX509.Certificate
	logTime time.Time
	log     Log
}

type LogTime struct {
	log      Log
	certType string
	time     time.Time
	index    int64
}

type InfoAboutTime struct {
	cert *ctX509.Certificate
	mas  []LogTime
}

type Log struct {
	Name  string
	Url   string
	Year  int
	start time.Time
	end   time.Time
}

type LogData struct {
	Entries []ct.LeafEntry
}

type StrangeCase1Log struct {
	info     InfoAboutTime
	log      Log
	timeLog  time.Time
	index    int64
	dif      time.Duration
	reason   string
	typeCert string
}

type StrangeCaseLogs struct {
	info InfoAboutTime
	difs []SmallDifLogs
}

type SmallDifLogs struct {
	log1      Log
	log2      Log
	typeCert1 string
	typeCert2 string
	timeLog1  time.Time
	timeLog2  time.Time
	index1    int64
	index2    int64
	dif       time.Duration
}

var logs = [9]Log{
	{"Yandex", "https://ct-agate.yandex.net/2025/", 2025, time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC), time.Date(2025, time.December, 31, 23, 59, 59, 0, time.UTC)},
	{"VK", "https://ctlog2025.mail.ru/nca2025/", 2025, time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC), time.Date(2025, time.December, 31, 23, 59, 59, 0, time.UTC)},
	{"MDC", "https://25.ctlog.digital.gov.ru/2025/", 2025, time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC), time.Date(2025, time.December, 31, 23, 59, 59, 0, time.UTC)},
	{"MDC", "https://24.ctlog.digital.gov.ru/2024/", 2024, time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC), time.Date(2024, time.December, 31, 23, 59, 59, 0, time.UTC)},
	{"VK", "https://ctlog2024.mail.ru/nca2024/", 2024, time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC), time.Date(2024, time.December, 31, 23, 59, 59, 0, time.UTC)},
	{"Yandex", "https://ct-agate.yandex.net/2024/", 2024, time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC), time.Date(2024, time.December, 31, 23, 59, 59, 0, time.UTC)},
	{"VK", "https://ctlog2023.mail.ru/nca2023/", 2023, time.Date(2023, time.January, 1, 0, 0, 0, 0, time.UTC), time.Date(2023, time.December, 31, 23, 59, 59, 0, time.UTC)},
	{"Yandex", "https://ct-agate.yandex.net/2023/", 2023, time.Date(2023, time.January, 1, 0, 0, 0, 0, time.UTC), time.Date(2024, time.February, 1, 0, 0, 0, 0, time.UTC)},
	{"Yandex", "https://ct-agate.yandex.net/2022/", 2022, time.Date(2022, time.January, 1, 0, 0, 0, 0, time.UTC), time.Date(2023, time.February, 1, 0, 0, 0, 0, time.UTC)},
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

func getAndParseCerts(startIndex int64, endIndex int64, masInfo map[string]*InfoAboutTime, log Log) {
	var i int64
	for i = startIndex; i < endIndex; i += 50 {
		certs := getCerts(i, i+49, log.Url)
		for j, leafEntry := range certs.Entries {
			parsedEntry, err := ct.LogEntryFromLeaf(i+int64(j), &leafEntry)
			if err != nil {
				fmt.Printf(err.Error())
			}
			var cert *ctX509.Certificate
			if parsedEntry.X509Cert != nil {
				logTime := LogTime{log, "cert", time.UnixMilli(int64(parsedEntry.Leaf.TimestampedEntry.Timestamp)), parsedEntry.Index}
				cert = parsedEntry.X509Cert
				info, ok := masInfo[cert.SerialNumber.String()]
				if ok {
					info.mas = append(info.mas, logTime)
				} else {
					mas := make([]LogTime, 0)
					info = &InfoAboutTime{cert: cert, mas: mas}
					info.mas = append(info.mas, logTime)
					masInfo[cert.SerialNumber.String()] = info
				}
			} else if parsedEntry.Precert != nil {
				logTime := LogTime{log, "precert", time.UnixMilli(int64(parsedEntry.Leaf.TimestampedEntry.Timestamp)), parsedEntry.Index}
				cert, err = ctX509.ParseCertificate(parsedEntry.Precert.Submitted.Data)
				if err != nil {
					logger.Println("Error parsing precert:", err)
					continue
				}
				info, ok := masInfo[cert.SerialNumber.String()]
				if ok {
					info.mas = append(info.mas, logTime)
				} else {
					mas := make([]LogTime, 0)
					info = &InfoAboutTime{cert: cert, mas: mas}
					info.mas = append(info.mas, logTime)
					masInfo[cert.SerialNumber.String()] = info
				}
			} else {
				fmt.Println("Incompatible values!")
				cert = nil
			}
		}
	}
}

func collectLogs() map[string]*InfoAboutTime {
	masInfo := make(map[string]*InfoAboutTime, 0)
	for i := 0; i < len(logs); i++ {
		size := getLenOfLog(logs[i].Url)
		getAndParseCerts(0, size, masInfo, logs[i])
	}
	return masInfo
}

func analysisDifBetweenLogs(mas map[string]*InfoAboutTime) []StrangeCaseLogs {
	caseManyLogs := make([]StrangeCaseLogs, 0)
	for _, info := range mas {
		strangeCase := StrangeCaseLogs{info: *info, difs: make([]SmallDifLogs, 0)}
		for i := 0; i < len(info.mas); i++ {
			for j := i + 1; j < len(info.mas); j++ {
				dif := info.mas[i].time.Sub(info.mas[j].time)
				if dif.Milliseconds() == 0 {
					smallDif := SmallDifLogs{log1: info.mas[i].log, log2: info.mas[j].log, timeLog1: info.mas[i].time, timeLog2: info.mas[j].time, dif: dif, typeCert1: info.mas[i].certType, typeCert2: info.mas[j].certType, index1: info.mas[i].index, index2: info.mas[j].index}
					strangeCase.difs = append(strangeCase.difs, smallDif)
					caseManyLogs = append(caseManyLogs, strangeCase)
				}
			}
		}
	}
	return caseManyLogs
}

func analysisDifBetweenLogAndCert(mas map[string]*InfoAboutTime) []StrangeCase1Log {
	cases := make([]StrangeCase1Log, 0)
	for _, info := range mas {
		for _, logInfo := range info.mas {
			if info.cert.NotAfter.Before(logInfo.log.start) || info.cert.NotAfter.After(logInfo.log.end) {
				var dif time.Duration
				if info.cert.NotAfter.Before(logInfo.log.start) {
					dif = logInfo.log.start.Sub(info.cert.NotAfter)
				} else {
					dif = info.cert.NotAfter.Sub(logInfo.log.end)
				}
				strangeCase := StrangeCase1Log{info: *info, log: logInfo.log, timeLog: logInfo.time, reason: "wrongLog", typeCert: logInfo.certType, dif: dif, index: logInfo.index}
				cases = append(cases, strangeCase)
			}

			if info.cert.NotBefore.After(logInfo.time) {
				strangeCase := StrangeCase1Log{info: *info, log: logInfo.log, timeLog: logInfo.time, reason: "timeInLogEarlierThanReleaseTime", typeCert: logInfo.certType, dif: info.cert.NotBefore.Sub(logInfo.time), index: logInfo.index}
				cases = append(cases, strangeCase)
				continue
			}

			dif := logInfo.time.Sub(info.cert.NotBefore)
			if dif.Milliseconds() <= 50 {
				strangeCase := StrangeCase1Log{info: *info, log: logInfo.log, timeLog: logInfo.time, dif: dif, reason: "tooSmallDifBetweenReleaseAndLogTime", typeCert: logInfo.certType, index: logInfo.index}
				cases = append(cases, strangeCase)
			}
		}
	}
	return cases
}
func buildingHistogramBetweenLogs(mas map[string]*InfoAboutTime) *charts.Bar {
	difs := make(map[int]int)
	maxValue := 0
	for _, info := range mas {
		var maxDif time.Duration
		for i := 0; i < len(info.mas); i++ {
			for j := i + 1; j < len(info.mas); j++ {
				dif1 := info.mas[i].time.Sub(info.mas[j].time)
				dif2 := info.mas[j].time.Sub(info.mas[i].time)
				maxDifCur := max(dif1, dif2)
				if maxDifCur > maxDif {
					maxDif = maxDifCur
				}
				if int(math.Floor(maxDifCur.Seconds())) > maxValue {
					maxValue = int(math.Ceil(maxDifCur.Seconds()))
				}
			}
		}
		difs[int(math.Floor(maxDif.Seconds()))] += 1
	}
	barNames := make([]string, 0)
	items := make([]opts.BarData, 0)
	for i := 0; i <= maxValue; i++ {
		n, ok := difs[i]
		if ok {
			barNames = append(barNames, strconv.Itoa(i)+"≤n<"+strconv.Itoa(i+1))
			items = append(items, opts.BarData{Value: n})
		}
	}
	bar := newBar("Varying of LogTime difference")
	bar.SetXAxis(barNames).AddSeries("number of certificates in logs", items)
	bar.SetGlobalOptions(
		charts.WithYAxisOpts(opts.YAxis{Type: "log"}),
		charts.WithDataZoomOpts(opts.DataZoom{
			Type:  "slider",
			Start: 0,
			End:   100,
		}),
		charts.WithXAxisOpts(opts.XAxis{
			Name: "interval, sec",
		}))
	return bar
}
func buildingHistogramBetweenLogAndCert(mas map[string]*InfoAboutTime) *charts.Bar {
	difs := make(map[int]int)
	maxValue := -10000000000
	minValue := 1000000000
	for _, info := range mas {
		minDif := int(info.mas[0].time.Sub(info.cert.NotBefore).Seconds())
		for _, logInfo := range info.mas {
			dif := int(math.Floor(logInfo.time.Sub(info.cert.NotBefore).Seconds()))
			minDif = min(minDif, dif)
			maxValue = max(maxValue, dif)
			minValue = min(minValue, dif)
		}
		difs[minDif] += 1
	}
	barNames := make([]string, 0)
	items := make([]opts.BarData, 0)
	for i := minValue; i <= maxValue; i++ {
		n, ok := difs[i]
		if ok {
			barNames = append(barNames, strconv.Itoa(i)+"≤n<"+strconv.Itoa(i+1))
			items = append(items, opts.BarData{Value: n})
		}
	}
	bar := newBar("Varying of LogTime and ReleaseTime difference")
	bar.SetXAxis(barNames).AddSeries("number of certificates", items)
	bar.SetGlobalOptions(
		charts.WithYAxisOpts(opts.YAxis{Type: "log"}),
		charts.WithDataZoomOpts(opts.DataZoom{
			Type:  "slider",
			Start: 0,
			End:   100,
		}),
		charts.WithXAxisOpts(opts.XAxis{
			Name: "interval, sec",
		}))
	return bar
}

func analysisTimeInLog(mas map[string]*InfoAboutTime) *charts.Bar {
	hours := make(map[int][]timeStatisticsLogs)
	for _, info := range mas {
		for _, logInfo := range info.mas {
			hours[logInfo.time.UTC().Hour()] = append(hours[logInfo.time.UTC().Hour()], timeStatisticsLogs{cert: info.cert, log: logInfo.log, logTime: logInfo.time})
		}
	}
	barNames := make([]string, 0)
	items := make([]opts.BarData, 0)
	for i := 0; i < 24; i++ {
		barNames = append(barNames, strconv.Itoa(i))
		items = append(items, opts.BarData{Value: len(hours[i])})
	}
	bar := newBar("Log Time (UTC)")
	bar.SetXAxis(barNames).
		AddSeries("number of certificates in logs", items)
	bar.SetGlobalOptions(charts.WithXAxisOpts(opts.XAxis{
		Name: "hours"}),
		charts.WithYAxisOpts(opts.YAxis{Type: "value"}),
	)
	return bar
}

func analysisTimeRelease(mas map[string]*InfoAboutTime) *charts.Bar {
	hours := make(map[int][]*ctX509.Certificate)
	for _, info := range mas {
		hours[info.cert.NotBefore.Hour()] = append(hours[info.cert.NotBefore.Hour()], info.cert)
	}
	barNames := make([]string, 0)
	items := make([]opts.BarData, 0)
	for i := 0; i < 24; i++ {
		barNames = append(barNames, strconv.Itoa(i))
		items = append(items, opts.BarData{Value: len(hours[i])})
	}
	bar := newBar("Release Time (UTC)")
	bar.SetXAxis(barNames).
		AddSeries("number of certificates", items)
	bar.SetGlobalOptions(charts.WithXAxisOpts(opts.XAxis{
		Name: "hours"}),
		charts.WithYAxisOpts(opts.YAxis{Type: "value"}))
	return bar
}

func plot(mas map[string]*InfoAboutTime, html string) {
	page := components.NewPage().SetPageTitle("Графики")
	page.InitAssets()
	page.AddCharts(
		analysisTimeInLog(mas),
		analysisTimeRelease(mas),
		buildingHistogramBetweenLogs(mas),
		buildingHistogramBetweenLogAndCert(mas),
	)
	f, err := os.Create("plots.html")
	if err != nil {
		panic(err)
	}
	page.Render(io.MultiWriter(f))
	f.WriteString(html)
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
					Lang:  []string{"Data view", "Turn off", "Refresh"},
				},
			}},
		),
	)
	return bar
}

func createCSVsData(mas1Log []StrangeCase1Log, masManyLogs []StrangeCaseLogs) ([][]string, [][]string, [][]string, [][]string) {
	//wrong log
	sort.Slice(mas1Log, func(i, j int) bool {
		return mas1Log[i].dif > mas1Log[j].dif
	})
	dataWrongLog := [][]string{
		{"CommonName", "Type", "CA", "SerialNumber", "LogIndex", "LogName", "LogYear", "ExpireTime", "Difference", "RawCertificate"},
	}
	for _, info := range mas1Log {
		if info.reason == "wrongLog" {
			str := []string{
				info.info.cert.Subject.CommonName,
				info.typeCert,
				info.info.cert.Issuer.CommonName,
				fmt.Sprintf("%X", info.info.cert.SerialNumber),
				fmt.Sprint(info.index),
				info.log.Name,
				strconv.Itoa(info.log.Year),
				info.info.cert.NotAfter.Format("2006-01-02 15:04:05.000"),
				info.dif.String(),
				base64.StdEncoding.EncodeToString(info.info.cert.Raw),
			}
			dataWrongLog = append(dataWrongLog, str)
		}
	}

	//timeInLogEarlierThanReleaseTime
	sort.Slice(mas1Log, func(i, j int) bool {
		return mas1Log[i].dif > mas1Log[j].dif
	})
	dataLogTimeEarlierThanRelease := [][]string{
		{"CommonName", "Type", "CA", "SerialNumber", "LogIndex", "LogName", "LogYear", "LogTime", "ReleaseTime", "Difference", "RawCertificate"},
	}
	for _, info := range mas1Log {
		if info.reason == "timeInLogEarlierThanReleaseTime" {
			str := []string{
				info.info.cert.Subject.CommonName,
				info.typeCert,
				info.info.cert.Issuer.CommonName,
				fmt.Sprintf("%X", info.info.cert.SerialNumber),
				fmt.Sprint(info.index),
				info.log.Name,
				strconv.Itoa(info.log.Year),
				info.timeLog.UTC().Format("2006-01-02 15:04:05.000"),
				info.info.cert.NotBefore.Format("2006-01-02 15:04:05.000"),
				info.dif.String(),
				base64.StdEncoding.EncodeToString(info.info.cert.Raw),
			}
			dataLogTimeEarlierThanRelease = append(dataLogTimeEarlierThanRelease, str)
		}
	}

	//tooSmallDifBetweenReleaseAndLogTime
	sort.Slice(mas1Log, func(i, j int) bool {
		return mas1Log[i].dif < mas1Log[j].dif
	})
	dataTooSmallDif := [][]string{
		{"CommonName", "Type", "CA", "SerialNumber", "LogIndex", "LogName", "LogYear", "LogTime", "ReleaseTime", "Difference", "RawCertificate"},
	}
	for _, info := range mas1Log {
		if info.reason == "tooSmallDifBetweenReleaseAndLogTime" {
			str := []string{
				info.info.cert.Subject.CommonName,
				info.typeCert,
				info.info.cert.Issuer.CommonName,
				fmt.Sprintf("%X", info.info.cert.SerialNumber),
				fmt.Sprint(info.index),
				info.log.Name,
				strconv.Itoa(info.log.Year),
				info.timeLog.UTC().Format("2006-01-02 15:04:05.000"),
				info.info.cert.NotBefore.Format("2006-01-02 15:04:05.000"),
				info.dif.String(),
				base64.StdEncoding.EncodeToString(info.info.cert.Raw)}
			dataTooSmallDif = append(dataTooSmallDif, str)
		}
	}

	//equalTimeInLogs
	dataEqualTimeLogs := [][]string{
		{"CommonName", "CA", "SerialNumber", "LogIndex1", "LogName1", "LogYear1", "Type1", "LogTime1", "LogIndex2", "LogName2", "LogYear2", "Type2", "LogTime2", "RawCertificate"},
	}
	for _, info := range masManyLogs {
		for _, dif := range info.difs {
			str := []string{
				info.info.cert.Subject.CommonName,
				info.info.cert.Issuer.CommonName,
				fmt.Sprintf("%X", info.info.cert.SerialNumber),
				fmt.Sprint(dif.index1),
				dif.log1.Name,
				strconv.Itoa(dif.log1.Year),
				dif.typeCert1,
				dif.timeLog1.UTC().Format("2006-01-02 15:04:05.000"),
				fmt.Sprint(dif.index2),
				dif.log2.Name,
				strconv.Itoa(dif.log2.Year),
				dif.typeCert2,
				dif.timeLog2.UTC().Format("2006-01-02 15:04:05.000"),
				base64.StdEncoding.EncodeToString(info.info.cert.Raw),
			}
			dataEqualTimeLogs = append(dataEqualTimeLogs, str)
		}
	}
	return dataWrongLog, dataLogTimeEarlierThanRelease, dataTooSmallDif, dataEqualTimeLogs

}

func csvWriter(data [][]string, name string) {
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

func main() {
	mas := collectLogs()
	cases1 := analysisDifBetweenLogAndCert(mas)
	cases2 := analysisDifBetweenLogs(mas)
	dataWrongLog, dataLogTimeEarlierThanRelease, dataTooSmallDif, dataEqualTimeLogs := createCSVsData(cases1, cases2)
	csvWriter(dataWrongLog, "wrong_log")
	csvWriter(dataLogTimeEarlierThanRelease, "log_time_earlier_than_release")
	csvWriter(dataTooSmallDif, "too_small_dif")
	csvWriter(dataEqualTimeLogs, "equal_time_in_dif_logs")
	plot(mas, "")
}
