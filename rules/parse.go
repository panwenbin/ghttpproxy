package rules

import (
	"encoding/json"
	"regexp"
)

func Parse(ruleBytes []byte) error {
	outR := OutRule{}
	err := json.Unmarshal(ruleBytes, &outR)
	if err != nil {
		return err
	}

	outR.OutRegexp, err = regexp.Compile(outR.Regexp)
	if err != nil {
		return err
	}

	return Apply(&outR)
}

func Apply(outR *OutRule) error {
	var err error
	if outR.OutRegexp == nil {
		outR.OutRegexp, err = regexp.Compile(outR.Regexp)
		if err != nil {
			return err
		}
	}
	OutMutex.Lock()
	defer OutMutex.Unlock()
	for i := range OutRules {
		if OutRules[i].Regexp == outR.Regexp {
			OutRules[i] = outR
			return nil
		}
	}

	OutRules = append(OutRules, outR)
	return nil
}
