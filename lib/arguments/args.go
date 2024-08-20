package arguments

import (
	"flag"
	"test_doh/lib/parameter"
)

func CmdParse(parse *parameter.Parses) {
	flag.StringVar(&parse.Domain, "domain", "", `待检测的域名`)
	flag.StringVar(&parse.File, "file", ``, `待检测域名的字典路径`)
	flag.BoolVar(&parse.Dns, "dns", false, `DNS请求方式`)
	flag.Parse()
}
