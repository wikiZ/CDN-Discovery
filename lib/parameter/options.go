package parameter

type Parses struct {
	Domain string
	File   string
	Dns    bool
}

const (
	BANNER = `
  ________  _  __  ___  _                              
 / ___/ _ \/ |/ / / _ \(_)__ _______ _  _____ ______ __
/ /__/ // /    / / // / (_-</ __/ _ \ |/ / -_) __/ // /
\___/____/_/|_/ /____/_/___/\__/\___/___/\__/_/  \_, / -V %s
Author By:%s                                  /___/  

Github:%s
`
	VERSION   = "24.08.20 Alpha"
	TITLE     = "CDN Discovery"
	LICENSE   = "GPL-2.0"
	URL       = "https://github.com/wikiZ/CDN-Discovery"
	AUTHOR    = "风起"
	TEAM      = "Independent Security Researcher"
	COPYRIGHT = "Copyright (C) 2024 风起. All Rights Reserved"
)
