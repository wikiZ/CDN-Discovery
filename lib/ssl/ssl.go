/**
 * @Author 风起
 * @contact: onlyzaliks@gmail.com
 * @File: ssl.go
 * @Time: 2023/4/29 21:44
 **/

package ssl

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"time"
)

func GetCertInfo(seedUrl string) (*x509.Certificate, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //Ignore certificate verification
			},
		},
		Timeout: 3 * time.Second, //Set the request timeout period
	}
	resp, err := client.Get(seedUrl)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.TLS.PeerCertificates[0], err
}
