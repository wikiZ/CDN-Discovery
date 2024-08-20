/**
 * @Author 风起
 * @contact: onlyzaliks@gmail.com
 * @File: dohQuery.go
 * @Time: 2024/8/18 23:40
 **/

package dns

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"test_doh/lib/log"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

// provider is provider
type provider uint

// Client is DoH provider client
type Client struct {
	provider provider
}

// Domain is dns query domain
type Domain string

const (
	// DefaultProvider is default provider
	DefaultProvider = iota
)

var (
	// upstreams is DoH upstreams
	upstreams = map[uint]string{
		DefaultProvider: "https://doh.pub/dns-query",
	}
	// httpClient is DoH http client
	httpClient = &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   3 * time.Second,
				KeepAlive: 60 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout: 3 * time.Second,
			DisableKeepAlives:   false,
			MaxIdleConns:        256,
			MaxIdleConnsPerHost: 256,
		},
	}
	logger = lib.Logger() // logger output model
)

// NewClient returns a new provider client
func NewClient() *Client {
	return &Client{
		provider: DefaultProvider,
	}
}

// String returns string of provider
func (c *Client) String() string {
	return "dnspod"
}

// Punycode returns punycode of domain
func (d Domain) Punycode() (string, error) {
	name := strings.TrimSpace(string(d))
	return idna.New(
		idna.MapForLookup(),
		idna.Transitional(true),
		idna.StrictDomainName(false),
	).ToASCII(name)
}

//func IsIPAddress(s string) []byte {
//	matches := regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`).FindAllString(s, -1)
//	for _, address := range matches {
//		if net.ParseIP(address) != nil {
//			return []byte(address)
//		}
//	}
//	return nil
//}

// Query do DoH query with the edns0-client-subnet option
func (c *Client) Query(ctx context.Context, d Domain) dns.Msg {
	name, _ := d.Punycode()
	query, _ := dns.Msg{}, url.Values{}
	query.SetQuestion(name, dns.TypeA)
	msg, _ := query.Pack()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, upstreams[uint(c.provider)], bytes.NewBuffer((msg)))
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-type", "application/dns-message")
	req.Header.Set("User-Agent", fmt.Sprintf("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"))
	//reqDump, _ := httputil.DumpRequestOut(req, true)
	//fmt.Println(string(reqDump))
	rsp, err := httpClient.Do(req)
	if err != nil {
		logger.Warning("请检查网络问题，DOH解析失败！")
		os.Exit(0)
	}
	bodyBytes, _ := ioutil.ReadAll(rsp.Body)
	response := dns.Msg{}
	response.Unpack(bodyBytes)
	defer rsp.Body.Close()
	return response
}

func LookupCNAMEWithServerForDoH(domain string) ([]string, dns.RR) {
	c := NewClient()
	ctx := context.Background()
	rsp := c.Query(ctx, Domain(domain))
	var (
		CNAMES  []string
		answers dns.RR
	)
	for _, answers = range rsp.Answer {
		if record, isType := answers.(*dns.CNAME); isType {
			CNAMES = append(CNAMES, record.Target)
		}
	}
	return CNAMES, answers
}

func LookupCNAMEForDoH(domain string) ([]string, dns.RR) {
	CNAMES, answers := LookupCNAMEWithServerForDoH(domain + ".")
	return CNAMES, answers
}
