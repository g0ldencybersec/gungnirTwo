package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/certificate-transparency-go/x509"
)

// Google's Log list schema
type LogList struct {
	Operators []struct {
		Name string `json:"name"`
		Logs []Log  `json:"logs"`
	} `json:"operators"`
}

type Log struct {
	URL   string `json:"url"`
	State struct {
		Usable struct {
			Timestamp string `json:"timestamp"`
		} `json:"usable"`
	} `json:"state"`
}

type CTMonitor struct {
	rootDomains map[string]bool
	logs        []string
}

// Checks if a domain is a subdomain of any root domain in the global map
func (m *CTMonitor) IsSubdomain(domain string) bool {
	if _, ok := m.rootDomains[domain]; ok {
		return true
	}

	parts := strings.Split(domain, ".")
	for i := range parts {
		parentDomain := strings.Join(parts[i:], ".")
		if _, ok := m.rootDomains[parentDomain]; ok {
			return true
		}
	}

	return false
}

func fetchLogList() ([]string, error) {
	resp, err := http.Get("https://www.gstatic.com/ct/log_list/v3/log_list.json")
	if err != nil {
		return nil, fmt.Errorf("failed to fetch log list: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	var logList LogList
	if err := json.Unmarshal(body, &logList); err != nil {
		return nil, fmt.Errorf("failed to unmarshal log list: %v", err)
	}

	var activeLogs []string
	for _, operator := range logList.Operators {
		for _, l := range operator.Logs {
			// A log is active if it has a usable timestamp
			if l.State.Usable.Timestamp != "" {
				url := l.URL
				if !strings.HasSuffix(url, "/") {
					url += "/"
				}
				if !strings.HasPrefix(url, "http") {
					url = "https://" + url
				}
				activeLogs = append(activeLogs, url)
			}
		}
	}

	if len(activeLogs) == 0 {
		return nil, fmt.Errorf("no active logs found")
	}

	return activeLogs, nil
}

func NewCTMonitor(rootDomains []string) (*CTMonitor, error) {
	logs, err := fetchLogList()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize log list: %v", err)
	}

	log.Printf("Initialized with %d CT logs", len(logs))

	roots := make(map[string]bool)
	for _, domain := range rootDomains {
		roots[domain] = true
	}

	return &CTMonitor{
		rootDomains: roots,
		logs:        logs,
	}, nil
}

func (m *CTMonitor) monitorLog(ctx context.Context, logURL string) error {
	client, err := client.New(logURL, &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}, jsonclient.Options{UserAgent: "g0lden_gungnir/2.0"})
	if err != nil {
		return fmt.Errorf("failed to create client: %v", err)
	}

	// Get the STH to find current tree size
	sth, err := client.GetSTH(ctx)
	if err != nil {
		return fmt.Errorf("failed to get STH: %v", err)
	}

	scanOpts := scanner.ScannerOptions{
		FetcherOptions: scanner.FetcherOptions{
			BatchSize:     1000,
			ParallelFetch: 10,
			EndIndex:      0,
			StartIndex:    int64(sth.TreeSize - uint64(100)),
			Continuous:    true,
		},
		Matcher:    NewSubdomainMatcher(m),
		NumWorkers: 10,
	}

	scanner := scanner.NewScanner(client, scanOpts)

	return scanner.Scan(ctx, m.logCertInfo, m.logPrecertInfo)
}

// Prints out a short bit of info about |cert|, found at |index| in the
// specified log
func (m *CTMonitor) logCertInfo(entry *ct.RawLogEntry) {
	parsedEntry, err := entry.ToLogEntry()
	if x509.IsFatal(err) || parsedEntry.X509Cert == nil {
		log.Printf("Process cert at index %d: <unparsed: %v>", entry.Index, err)
	} else {
		log.Printf("Process cert at index %d: CN: '%s'", entry.Index, parsedEntry.X509Cert.Subject.CommonName)
	}
}

// Prints out a short bit of info about |precert|, found at |index| in the
// specified log
func (m *CTMonitor) logPrecertInfo(entry *ct.RawLogEntry) {
	parsedEntry, err := entry.ToLogEntry()
	if x509.IsFatal(err) || parsedEntry.Precert == nil {
		log.Printf("Process precert at index %d: <unparsed: %v>", entry.Index, err)
	} else {
		log.Printf("Process precert at index %d: CN: '%s' Issuer: %s", entry.Index, parsedEntry.Precert.TBSCertificate.Subject.CommonName, parsedEntry.Precert.TBSCertificate.Issuer.CommonName)
	}
}

func (m *CTMonitor) Start(ctx context.Context) {
	for _, logURL := range m.logs {
		go func(url string) {
			for {
				if err := m.monitorLog(ctx, url); err != nil {
					log.Printf("Error monitoring log %s: %v", url, err)
					time.Sleep(time.Minute)
				}
			}
		}(logURL)
	}
}

func (m *CTMonitor) handleGetCerts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode("google.com") //TODO fix
}

func main() {
	ctx := context.Background()
	monitor, err := NewCTMonitor([]string{"google.com", "zendesk.com", "cisco.com"}) // Replace with your root domain
	if err != nil {
		log.Fatalf("Failed to create monitor: %v", err)
	}

	monitor.Start(ctx)

	http.HandleFunc("/certs", monitor.handleGetCerts)

	log.Printf("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
