/**
 * @Author 风起
 * @contact: onlyzaliks@gmail.com
 * @File: uri.go
 * @Time: 2023/4/28 12:02
 **/

package uri

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net"
)

func LastIP(network *net.IPNet) net.IP {
	mask, _ := network.Mask.Size()
	lastIP := toIP(toInt(FirstIP(network)) + uint32(math.Pow(2, float64(32-mask))) - 1)
	return net.ParseIP(lastIP)
}

func FirstIP(network *net.IPNet) net.IP {
	return network.IP
}

func Contains(network *net.IPNet, ip net.IP) bool {
	i := toInt(ip)
	return toInt(FirstIP(network)) < i && toInt(LastIP(network)) > i
}

func SameSegment(ips ...string) bool {
	if len(ips) == 0 {
		return true
	}
	first := ips[0]
	_, network, _ := net.ParseCIDR(first + "/24")
	for _, ip := range ips[1:] {
		if ip != "" && Contains(network, net.ParseIP(ip)) == false {
			return false
		}
	}
	return true
}

// converts an IP address to its integer representation.
func toInt(ip net.IP) uint32 {
	var buf = []byte(ip)
	if len(buf) > 12 {
		buf = buf[12:]
	}
	var i uint32
	_ = binary.Read(bytes.NewBuffer(buf), binary.BigEndian, &i)
	return i
}

func toIP(i uint32) string {
	buf := bytes.NewBuffer([]byte{})
	_ = binary.Write(buf, binary.BigEndian, i)
	b := buf.Bytes()
	return fmt.Sprintf("%v.%v.%v.%v", b[0], b[1], b[2], b[3])
}
