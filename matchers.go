package main

import (
	"strings"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"
)

type SubdomainMatcher struct {
	monitor *CTMonitor
}

func NewSubdomainMatcher(monitor *CTMonitor) *SubdomainMatcher {
	return &SubdomainMatcher{
		monitor: monitor,
	}
}

// CertificateMatches implements scanner.Matcher
func (m *SubdomainMatcher) CertificateMatches(cert *x509.Certificate) bool {
	// Check CommonName if it exists
	if cert.Subject.CommonName != "" && !m.monitor.IsSubdomain(cert.Subject.CommonName) {
		return false
	}

	// Check all SANs - if any are not subdomains, return false
	for _, san := range cert.DNSNames {
		if !m.monitor.IsSubdomain(san) {
			return false
		}
	}

	// If we got here, all domains were subdomains
	// But make sure we had at least one domain to check
	return len(cert.DNSNames) > 0 || cert.Subject.CommonName != ""
}

// PrecertificateMatches implements scanner.Matcher
func (m *SubdomainMatcher) PrecertificateMatches(precert *ct.Precertificate) bool {
	// Check CommonName if it exists
	if precert.TBSCertificate.Subject.CommonName != "" && !m.monitor.IsSubdomain(precert.TBSCertificate.Subject.CommonName) {
		return false
	}

	// Check all SANs - if any are not subdomains, return false
	for _, san := range precert.TBSCertificate.DNSNames {
		if !m.monitor.IsSubdomain(san) {
			return false
		}
	}

	// If we got here, all domains were subdomains
	// But make sure we had at least one domain to check
	return len(precert.TBSCertificate.DNSNames) > 0 || precert.TBSCertificate.Subject.CommonName != ""
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
