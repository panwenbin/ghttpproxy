package rules

import (
	"regexp"
)

type OutRule struct {
	Regexp    string `json:"regexp"`
	OutRegexp *regexp.Regexp
	OutType   string `json:"out_type"`
	OutServer string `json:"out_server"`
	Group     string `json:"group"`
}
