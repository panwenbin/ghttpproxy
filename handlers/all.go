package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/panwenbin/ghttpclient"
	"github.com/panwenbin/ghttpclient/header"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Hop-by-hop headers. These are removed when sent to the backend.
// As of RFC 7230, hop-by-hop headers are required to appear in the
// Connection header field. These are the headers defined by the
// obsoleted RFC 2616 (section 13.5.1) and are used for backward
// compatibility.
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection", // non-standard but still sent by libcurl and rejected by e.g. google
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",      // canonicalized version of "TE"
	"Trailer", // not Trailers per URL above; https://www.rfc-editor.org/errata_search.php?eid=4522
	"Transfer-Encoding",
	"Upgrade",
}

func isLocalIp(ipStr string) bool {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Fatalln(err)
	}
	ipStrCheck := ipStr + "/"
	for i := range interfaces {
		addrs, err := interfaces[i].Addrs()
		if err != nil {
			log.Fatalln(err)
		}
		for j := range addrs {
			addr := addrs[j]
			if addr.Network() == "ip+net" {
				addrStr := addr.String()
				if strings.Compare(addrStr, ipStr) == 0 || strings.Index(addrStr, ipStrCheck) == 0 {
					return true
				}
			}
		}
	}
	return false
}

func All(writer http.ResponseWriter, request *http.Request) {
	if isLocalIp(request.Host) {
		setting(writer, request)
		return
	}
	headers := header.GHttpHeader{}
	for k, vv := range request.Header {
		for _, v := range vv {
			headers.Set(k, v)
		}
	}
	if acceptEncoding, ok := headers["Accept-Encoding"]; ok && strings.Contains(acceptEncoding, "gzip") {
		headers["Accept-Encoding"] = "gzip"
	}
	for _, hopHeader := range hopHeaders {
		if _, ok := headers[hopHeader]; ok {
			delete(headers, hopHeader)
		}
	}
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	reqBody, err := ioutil.ReadAll(request.Body)
	if err != nil {
		writer.Write([]byte("read request body err"))
		return
	}
	client := ghttpclient.NewClient().Url(scheme + "://" + request.Host + request.RequestURI).Headers(headers).NoRedirect(true)
	switch request.Method {
	case "GET":
		client = client.Get()
	case "POST":
		client = client.Body(bytes.NewReader(reqBody)).Post()
	default:
		writer.Write([]byte(request.Method + " is not supported yet"))
		return
	}
	response, err := client.Response()
	if err != nil {
		writer.Write([]byte("get response err: " + err.Error()))
		return
	}

	contentType := response.Header.Get("Content-Type")
	switch {
	case strings.Contains(contentType, "text"), strings.Contains(contentType, "javascript"), strings.Contains(contentType, "json"):
		err = proxy(response, writer, request, reqBody)
	default:
		err = pass(response, writer, request, reqBody)
	}
	if err != nil {
		writer.Write([]byte("err occurs: " + err.Error()))
	}
}

var outDomainMap = make(map[string]string, 0)
var outRules = make([]*outRule, 0)
var outMutex = sync.RWMutex{}

type outRule struct {
	Regexp    string `json:"regexp"`
	OutRegexp *regexp.Regexp
	OutType   string `json:"out_type"`
	OutServer string `json:"out_server"`
}

type out struct {
	Method         string      `json:"method"`
	Uri            string      `json:"uri"`
	RequestHeader  http.Header `json:"request_header"`
	RequestBody    string      `json:"request_body"`
	ResponseHeader http.Header `json:"response_header"`
	ResponseBody   string      `json:"response_body"`
}

func checkOut(request *http.Request) (string, string) {
	uri := request.Host + request.RequestURI
	outMutex.RLock()
	for i := range outRules {
		if outRules[i].OutRegexp.MatchString(uri) {
			return outRules[i].OutType, outRules[i].OutServer
		}
	}

	outSetting, ok := outDomainMap[request.Host]
	if !ok {
		outSetting, ok = outDomainMap["*"]
	}
	outType := "none"
	outServer := ""
	outMutex.RUnlock()
	if ok {
		splits := strings.SplitN(outSetting, ":", 2)
		outType = splits[0]
		outServer = splits[1]
		if strings.Contains(outServer, "remote") {
			remoteHost := strings.Split(request.RemoteAddr, ":")[0]
			outServer = strings.Replace(outServer, "remote", remoteHost, 1)
		}
	}

	return outType, outServer
}

func prepareOut(request *http.Request, response *http.Response, reqBody []byte, resBody []byte) []byte {
	o := out{
		Method:         request.Method,
		Uri:            request.Host + request.RequestURI,
		RequestHeader:  request.Header,
		RequestBody:    string(reqBody),
		ResponseHeader: response.Header,
		ResponseBody:   string(resBody),
	}

	outBody, _ := json.Marshal(o)
	return outBody
}

func proxy(response *http.Response, writer http.ResponseWriter, request *http.Request, reqBody []byte) error {
	h := writer.Header()
	for k, vv := range response.Header {
		if k == "Content-Encoding" {
			continue
		}
		if k == "Content-Length" {
			continue
		}
		for _, v := range vv {
			h.Add(k, v)
		}
	}
	for _, hopHeader := range hopHeaders {
		if _, ok := h[hopHeader]; ok {
			delete(h, hopHeader)
		}
	}
	resBody, err := ghttpclient.ReadBodyClose(response)
	if err != nil {
		return errors.New("read body err: " + err.Error())
	}
	outType, outServer  := checkOut(request)
	switch outType {
	case "chan":
		outBody := prepareOut(request, response, reqBody, resBody)
		resBody, err = ghttpclient.PostJson("http://"+outServer+"/chan", outBody, nil).ReadBodyClose()
		if err != nil {
			log.Println(err)
		}
	case "log":
		outBody := prepareOut(request, response, reqBody, resBody)
		go ghttpclient.PostJson("http://"+outServer+"/log", outBody, nil).ReadBodyClose()
	}
	h.Set("Content-Length", strconv.Itoa(len(resBody)))
	writer.WriteHeader(response.StatusCode)
	_, err = writer.Write(resBody)
	return err
}

func pass(response *http.Response, writer http.ResponseWriter, request *http.Request, reqBody []byte) error {
	outType, outServer  := checkOut(request)
	switch outType {
	case "log":
		outBody := prepareOut(request, response, reqBody, nil)
		go ghttpclient.PostJson("http://"+outServer+"/log", outBody, nil).ReadBodyClose()
	}
	defer response.Body.Close()
	h := writer.Header()
	for k, vv := range response.Header {
		for _, v := range vv {
			h.Set(k, v)
		}
	}
	writer.WriteHeader(response.StatusCode)

	buf := make([]byte, 32*1024)
	for {
		n, err := response.Body.Read(buf)
		if err != nil && err != io.EOF && err != context.Canceled {
			return errors.New("read body err: " + err.Error())
		}
		if n > 0 {
			_, err = writer.Write(buf[:n])
			if err != nil {
				return err
			}
		} else {
			break
		}
	}

	return nil
}

func setting(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case "GET":
		splits := strings.Split(request.RequestURI, "/")
		if len(splits) == 3 {
			domain := splits[1]
			outType := splits[2]
			outMutex.Lock()
			switch outType {
			case "none":
				delete(outDomainMap, domain)
			default:
				outDomainMap[domain] = outType
			}
			outMutex.Unlock()
			writer.Write([]byte("set " + domain + " : " + outType + "\n"))
			return
		} else {
			outJson, err := json.Marshal(map[string]interface{}{
				"out_rules": outRules,
				"out_domains": outDomainMap,
			})
			if err != nil {
				log.Println(err)
				return
			}
			writer.Write(outJson)
			return
		}
	case "POST":
		reqBody, err := ioutil.ReadAll(request.Body)
		if err != nil {
			log.Println(err)
			writer.Write([]byte("read body err"))
			return
		}

		outR := outRule{}
		err = json.Unmarshal(reqBody, &outR)
		if err != nil {
			log.Println(err)
			writer.Write([]byte("json unmarshal err"))
			return
		}

		outMutex.Lock()
		defer outMutex.Unlock()
		outR.OutRegexp, err = regexp.Compile(outR.Regexp)
		if err != nil {
			log.Println(err)
			writer.Write([]byte("regexp err"))
			return
		}
		for i:= range outRules {
			if outRules[i].Regexp == outR.Regexp {
				outRules[i] = &outR
				writer.Write([]byte("set " + outR.Regexp + " : " + outR.OutType + "\n"))
				return
			}
		}
		outRules = append(outRules, &outR)
		writer.Write([]byte("set " + outR.Regexp + " : " + outR.OutType + "\n"))
		return
	}
}
