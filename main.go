package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
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
	Description string `json:"description"`
	LogID       string `json:"log_id"`
	Key         string `json:"key"`
	URL         string `json:"url"`
	MMD         int    `json:"mmd"`
	State       struct {
		Usable struct {
			Timestamp string `json:"timestamp"`
		} `json:"usable"`
	} `json:"state"`
	TemporalInterval struct {
		StartInclusive string `json:"start_inclusive"`
		EndExclusive   string `json:"end_exclusive"`
	} `json:"temporal_interval"`
}

type CertInfo struct {
	CommonName string    `json:"common_name"`
	SANs       []string  `json:"sans"`
	Issuer     string    `json:"issuer"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	LogURL     string    `json:"log_url"`
	SeenAt     time.Time `json:"seen_at"`
}

type CTMonitor struct {
	rootDomain string
	certs      map[string]CertInfo
	mu         sync.RWMutex
	logs       []string
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
				fmt.Println(l.URL)
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

func NewCTMonitor(rootDomain string) (*CTMonitor, error) {
	logs, err := fetchLogList()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize log list: %v", err)
	}

	log.Printf("Initialized with %d CT logs", len(logs))
	for _, logURL := range logs {
		log.Printf("Using log: %s", logURL)
	}

	return &CTMonitor{
		rootDomain: rootDomain,
		certs:      make(map[string]CertInfo),
		logs:       logs,
	}, nil
}

func (m *CTMonitor) isRelevantDomain(domain string) bool {
	return strings.HasSuffix(domain, "."+m.rootDomain) || domain == m.rootDomain
}

func (m *CTMonitor) processCertificate(entry *ct.RawLogEntry, logURL string) {
	var cert *x509.Certificate
	var err error

	switch entry.Leaf.TimestampedEntry.EntryType {
	case ct.X509LogEntryType:
		cert, err = x509.ParseCertificate(entry.Leaf.TimestampedEntry.X509Entry.Data)
	case ct.PrecertLogEntryType:
		cert, err = x509.ParseCertificate(entry.Leaf.TimestampedEntry.PrecertEntry.TBSCertificate)
	default:
		log.Printf("Unknown entry type: %v", entry.Leaf.TimestampedEntry.EntryType)
		return
	}

	if err != nil {
		log.Printf("Failed to parse certificate: %v", err)
		return
	}

	relevant := false
	if m.isRelevantDomain(cert.Subject.CommonName) {
		relevant = true
	}
	for _, san := range cert.DNSNames {
		if m.isRelevantDomain(san) {
			relevant = true
			break
		}
	}

	if !relevant {
		return
	}

	certInfo := CertInfo{
		CommonName: cert.Subject.CommonName,
		SANs:       cert.DNSNames,
		Issuer:     cert.Issuer.CommonName,
		NotBefore:  cert.NotBefore,
		NotAfter:   cert.NotAfter,
		LogURL:     logURL,
		SeenAt:     time.Now(),
	}

	m.mu.Lock()
	m.certs[cert.Subject.CommonName] = certInfo
	m.mu.Unlock()

	log.Printf("Found new certificate for domain %s", cert.Subject.CommonName)
}

func (m *CTMonitor) monitorLog(ctx context.Context, logURL string) error {
	opts := jsonclient.Options{}
	client, err := client.New(logURL, &http.Client{}, opts)
	if err != nil {
		return fmt.Errorf("failed to create client: %v", err)
	}

	scanOpts := scanner.ScannerOptions{
		FetcherOptions: scanner.FetcherOptions{
			BatchSize:     1000,
			ParallelFetch: 5,
			EndIndex:      0,
			Continuous:    true,
		},
		NumWorkers: 5,
	}

	scanner := scanner.NewScanner(client, scanOpts)

	certMatcherFunc := func(entry *ct.RawLogEntry) {
		m.processCertificate(entry, logURL)
	}

	return scanner.Scan(ctx, certMatcherFunc, certMatcherFunc)
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
	m.mu.RLock()
	defer m.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(m.certs)
}

func main() {
	ctx := context.Background()
	monitor, err := NewCTMonitor("cisco.com") // Replace with your root domain
	if err != nil {
		log.Fatalf("Failed to create monitor: %v", err)
	}

	monitor.Start(ctx)

	http.HandleFunc("/certs", monitor.handleGetCerts)

	log.Printf("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
