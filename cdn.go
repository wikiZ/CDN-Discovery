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
	"strings"

	"test_doh/lib/arguments"
	"test_doh/lib/dns"
	"test_doh/lib/finger"
	"test_doh/lib/log"
	"test_doh/lib/parameter"
	"test_doh/lib/ssl"
	"test_doh/lib/uri"

	"github.com/projectdiscovery/cdncheck"
)

type Init struct {
	Parses parameter.Parses
}

var logger = lib.Logger() // logger output model

func NewParameter() *Init {
	return &Init{}
}

// FindWithDomain Check Whether the domain name is a CDN asset
// @param	domain	  string	Domain name to be verified
func (i *Init) FindWithDomain(domain string) bool {
	checkResultBool, cdnCheckBool := false, false //init Rank value and asset describe
	IPs, _ := dns.LookupIP(domain)                //Get Domain Addresses List
	var CNAMES []string
	if i.Parses.Dns {
		CNAMES = dns.LookupCNAME(domain)
	}
	CNAMES, answers := dns.LookupCNAMEForDoH(domain)
	if uri.SameSegment(IPs...) == false {
		checkResultBool = true
		logger.Emergencyf("[*] 域名指向多个IP地址，且不在同一网段，该域名可能使用了CDN技术 ")
	}

	// Checks whether the IP address string is an Intranet address
	for _, ip := range IPs {
		if i.HasLocalIPAddr(ip) {
			logger.Warning("[*] 局域网地址,非公网IP地址")
			return false
		}
		if !cdnCheckBool {
			//Init cdn check project
			client := cdncheck.New()
			// checks if an IP is contained in the cdn denylist
			if matched, val, _ := client.CheckCDN(net.ParseIP(ip)); matched {
				checkResultBool, cdnCheckBool = true, true
				logger.Emergencyf("[*] 境外CDNcheck判定使用CDN服务：%s", val)
			}
			//Check whether the TLS certificate has CDN-related features
			if b, s := i.HasCertInfo(ip); b {
				checkResultBool, cdnCheckBool = true, true
				logger.Emergencyf("[*] 目标IP节点HTTPS证书中存在CDN敏感关键字: %s", s)
			}
		}
	}
	cdnCheckBool = false // init cdnCheckBool
	// Check whether the CNAME has CDN-related features
	for _, cname := range CNAMES {
		if !cdnCheckBool {
			if regexp.MustCompile("(?i)cdn|(?i)jiasu|(?i)proxy").MatchString(cname) {
				checkResultBool, cdnCheckBool = true, true
				logger.Emergencyf("[*] 域名CNAME存在CDN关键字")
			}
			// Try to match the CNAME fingerprint
			for _, domain := range i.parseBaseCname(cname) {
				for _, item := range finger.DomainItems {
					if item.Domain == domain {
						checkResultBool, cdnCheckBool = true, true
						logger.Emergencyf("[*] 域名CNAME命中指纹:%s", item.Name)
					}
				}
			}
		}
	}
	if checkResultBool {
		logger.Notice("目标域名可能使用CDN服务！\n")
	} else if answers == nil {
		logger.Warning("目标域名无法正常解析，可能已停止服务！\n")
		return checkResultBool
	} else {
		logger.Error("目标域名未使用CDN服务！\n")
	}
	return checkResultBool

}

func (i *Init) parseBaseCname(cname string) (result []string) {
	parts := strings.Split(cname, ".")
	size := len(parts)
	if size == 0 {
		return []string{}
	}
	cname = parts[size-1]
	result = append(result, cname)
	for i := len(parts) - 2; i >= 0; i-- {
		cname = parts[i] + "." + cname
		if len(cname) > 0 && cname[len(cname)-1] == '.' {
			// If the string is not empty and the last character is '.', remove it by slicing
			cname = cname[:len(cname)-1]
		}
		result = append(result, cname)
	}
	return result
}

// HasCertInfo	Check whether the asset is a LAN address
// @param	ip	  net.IP	internet ip address
func (i *Init) HasCertInfo(ip string) (bool, string) {
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
	if regexp.MustCompile("(?i)cdn|(?i)jiasu|(?i)proxy").MatchString(commonName) {
		return true, ""
	}
	return false, ""
}

func (i *Init) HasLocalIPAddr(ip string) bool {
	return i.HasLocalIP(net.ParseIP(ip))
}

// HasLocalIP	Check whether the asset is a LAN address
// @param	ip	  net.IP	internet ip address
func (i *Init) HasLocalIP(ip net.IP) bool {
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
	fmt.Println(fmt.Sprintf(parameter.BANNER, parameter.VERSION, parameter.AUTHOR, parameter.URL))
	cmd := NewParameter()
	arguments.CmdParse(&cmd.Parses)
	checkDomainFunction := func(domain string) bool {
		return arguments.IsValidDomain(domain)
	}
	switch {
	case cmd.Parses.Domain == "" && cmd.Parses.File == "":
		logger.Warning("域名或文件路径不能为空，请指定参数！")
	case cmd.Parses.File != "":
		for _, domain := range arguments.ReadFile(cmd.Parses.File) {
			logger.Alertf("Domain Address：%s", domain)
			if !checkDomainFunction(domain) {
				continue
			}
			cmd.FindWithDomain(domain)
		}
	default:
		domain := cmd.Parses.Domain
		logger.Alertf("Domain Address：%s", domain)
		if !checkDomainFunction(domain) {
			os.Exit(0)
		}
		cmd.FindWithDomain(domain)
	}
}
