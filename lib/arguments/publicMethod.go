package arguments

import (
	"bufio"
	"fmt"
	"os"
	"regexp"

	"test_doh/lib/log"
)

var logger = lib.Logger() // logger output model

func ReadFile(filepath string) []string {
	var fileDomainList []string
	file, err := os.Open(filepath)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return nil
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fileDomainList = append(fileDomainList, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		fmt.Println("Error reading file:", err)
		return nil
	}
	return fileDomainList
}

func IsValidDomain(domain string) bool {
	re := regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	if !re.MatchString(domain) {
		logger.Warning("非合法域名地址，请检查域名格式！\n")
	}
	return re.MatchString(domain)
}
