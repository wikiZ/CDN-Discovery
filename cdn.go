/**
 * @Author 风起
 * @contact: onlyzaliks@gmail.com
 * @File: cdn.go
 * @Time: 2023/4/28 12:01
 **/

package main

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"cdn/lib/dns"
	"cdn/lib/finger"
	"cdn/lib/ssl"
	"cdn/lib/uri"

	"github.com/projectdiscovery/cdncheck"
)

// FindWithDomain Check Whether the domain name is a CDN asset
// @param	domain	  string	Domain name to be verified
func FindWithDomain(domain string) (bool, string, int) {
	rank, describe := 0, ""        //init Rank value and asset describe
	IPs, _ := dns.LookupIP(domain) //Get Domain Addresses List
	CNAMES, _ := dns.LookupCNAME(domain)
	if uri.SameSegment(IPs...) == false {
		rank += 60
		describe = "域名指向多个IP地址，且不在同一网段，该域名可能使用了CDN技术 "
	}

	// Checks whether the IP address string is an Intranet address
	for _, ip := range IPs {
		if HasLocalIPAddr(ip) {
			return false, "局域网地址", 0
		}
		//Init dncheck project
		client := cdncheck.New()
		// checks if an IP is contained in the cdn denylist
		matched, val, _ := client.CheckCDN(net.ParseIP(ip))
		if matched {
			rank += 30
			describe = fmt.Sprintf("%s%s", describe, val)
		} else if rank > 30 {
			//Check whether the TLS certificate has CDN-related features
			if b, s := HasCertInfo(ip); b {
				rank += 30
				describe = fmt.Sprintf("%s%s", describe, s)
				goto LOOK
			}
		}
	}
	// Check whether the CNAME has CDN-related features
	for _, cname := range CNAMES {
		if regexp.MustCompile("(?i)cdn").MatchString(cname) {
			return true, "该域名可能使用了CDN技术 " + describe, 100
		}
		//Try to match the CNAME fingerprint
		for _, domain := range parseBaseCname(cname) {
			for _, item := range finger.DomainItems {
				if item.Domain == domain {
					return true, item.Name, 100
				}
			}
		}
	}
LOOK:
	if rank != 0 {
		return true, describe, rank
	}
	return false, describe, 0
}

func parseBaseCname(cname string) (result []string) {
	parts := strings.Split(cname, ".")
	size := len(parts)
	if size == 0 {
		return []string{}
	}
	cname = parts[size-1]
	result = append(result, cname)
	for i := len(parts) - 2; i >= 0; i-- {
		cname = parts[i] + "." + cname
		result = append(result, cname)
	}
	return result
}

// HasCertInfo	Check whether the asset is a LAN address
// @param	ip	  net.IP	internet ip address
func HasCertInfo(ip string) (bool, string) {
	sslCert, err := ssl.GetCertInfo("https://" + ip)
	if err != nil {
		return false, ""
	}
	commonName := fmt.Sprintf("%s", sslCert.Subject.CommonName)
	// Check TLS Cert commonName fingerprint
	for _, subject := range finger.DomainItems {
		if strings.Contains(commonName, subject.Domain) {
			return true, subject.Name
		}
	}
	// Check TLS Cert keyword
	if regexp.MustCompile("(?i)cdn||(?i)jiasu").MatchString(commonName) {
		return true, ""
	}
	return false, ""
}

func HasLocalIPAddr(ip string) bool {
	return HasLocalIP(net.ParseIP(ip))
}

// HasLocalIP	Check whether the asset is a LAN address
// @param	ip	  net.IP	internet ip address
func HasLocalIP(ip net.IP) bool {
	if ip.IsLoopback() {
		return true
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}

	return ip4[0] == 127 || ip4[0] == 10 || // 10.0.0.0/8
		(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) || // 172.16.0.0/12
		(ip4[0] == 169 && ip4[1] == 254) || // 169.254.0.0/16
		(ip4[0] == 192 && ip4[1] == 168) // 192.168.0.0/16
}

func main() {
	if net.ParseIP(os.Args[1]) == nil {
		b, s, r := FindWithDomain(os.Args[1])
		fmt.Println("bool:" + strconv.FormatBool(b) + " str:" + s + " rank:" + strconv.Itoa(r))
	}
}
