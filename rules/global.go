package rules

import "sync"

var OutRules = make([]*OutRule, 0)
var OutMutex = sync.RWMutex{}
