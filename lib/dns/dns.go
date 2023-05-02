/**
 * @Author 风起
 * @contact: onlyzaliks@gmail.com
 * @File: dns.go
 * @Time: 2023/4/28 12:24
 **/

package dns

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// domainServers Set Agent Addr
var domainServers = []string{
	"114.114.114.114:53",
	//"8.8.8.8:53",
	"223.6.6.6:53",
}

var resolvers = generateResolver()

func LookupCNAME(domain string) ([]string, error) {
	var lastErr error
	for _, domainServer := range domainServers {
		CNAMES, err := LookupCNAMEWithServer(domain, domainServer)
		if err != nil {
			lastErr = err
		}
		return CNAMES, nil
	}
	return nil, lastErr
}

func LookupCNAMEWithServer(domain, domainServer string) ([]string, error) {
	c := dns.Client{
		Timeout: 3 * time.Second,
	}
	var CNAMES []string
	m := dns.Msg{}
	/*
		It will eventually point to an ip
		which is typeA, which will return the cnames of all layers
	*/
	m.SetQuestion(domain+".", dns.TypeA)
	r, _, err := c.Exchange(&m, domainServer)
	if err != nil {
		return nil, err
	}
	for _, ans := range r.Answer {
		if record, isType := ans.(*dns.CNAME); isType {
			CNAMES = append(CNAMES, record.Target)
		}
	}
	return CNAMES, nil
}

func LookupIP(domain string) ([]string, error) {
	var (
		lastErr error
		IPs     []string
	)
	for _, resolver := range resolvers {
		ips, err := resolver.LookupIPAddr(context.Background(), domain)
		if err != nil {
			lastErr = err
		}
		for _, v := range ips {
			IPs = append(IPs, v.IP.String())
		}
	}
	return RemoveDuplicateElement(IPs), lastErr
}

func generateResolver() []*net.Resolver {
	var resolvers []*net.Resolver
	for _, server := range domainServers {
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout: 3 * time.Second,
				}
				return d.DialContext(ctx, "udp", server)
			},
		}
		resolvers = append(resolvers, resolver)
	}
	return resolvers
}

func RemoveDuplicateElement[T any](slice []T) []T {
	slice = append(slice)
	set := make(map[string]struct{}, len(slice))
	j := 0
	for _, v := range slice {
		_, ok := set[fmt.Sprint(v)]
		if ok {
			continue
		}
		set[fmt.Sprint(v)] = struct{}{}
		slice[j] = v
		j++
	}
	return slice[:j]
}
