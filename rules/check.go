package rules

import "net/http"

func Check(request *http.Request) (string, string, string) {
	uri := request.Host + request.RequestURI
	OutMutex.RLock()
	defer OutMutex.RUnlock()
	for i := range OutRules {
		if OutRules[i].OutRegexp.MatchString(uri) {
			return OutRules[i].OutType, OutRules[i].OutServer, OutRules[i].Group
		}
	}

	return "none", "", ""
}
