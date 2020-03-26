package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/panwenbin/ghttpclient"
	"github.com/panwenbin/ghttpclient/header"
	"io"
	"io/ioutil"
	"log"
	"net/http"
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

func All(writer http.ResponseWriter, request *http.Request) {
	if request.Host == "127.0.0.1" {
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
	client := ghttpclient.NewClient().Url(scheme + "://" + request.Host + request.RequestURI).Headers(headers).NoRedirect(true)
	switch request.Method {
	case "GET":
		client = client.Get()
	case "POST":
		client = client.Body(request.Body).Post()
	default:
		writer.Write([]byte(request.Method + " is not supported yet"))
		return
	}
	res, err := client.Response()
	if err != nil {
		writer.Write([]byte("get response err: " + err.Error()))
		return
	}

	contentType := res.Header.Get("Content-Type")
	switch {
	case strings.Contains(contentType, "text"), strings.Contains(contentType, "javascript"), strings.Contains(contentType, "json"):
		err = proxy(res, writer, request)
	default:
		err = pass(res, writer, request)
	}
	if err != nil {
		writer.Write([]byte("err occurs: " + err.Error()))
	}
}

var outDomainMap = make(map[string]string, 0)
var outDomainMapMutex = sync.RWMutex{}

type out struct {
	Method         string      `json:"method"`
	Uri            string      `json:"uri"`
	RequestHeader  http.Header `json:"request_header"`
	RequestBody    string      `json:"request_body"`
	ResponseHeader http.Header `json:"response_header"`
	ResponseBody   string      `json:"response_body"`
}

func outPrepare(request *http.Request, response *http.Response, body []byte) (string, string, []byte) {
	outDomainMapMutex.RLock()
	outSetting, ok := outDomainMap[request.Host]
	if !ok {
		outSetting, ok = outDomainMap["*"]
	}
	outType := ""
	outServer := ""
	outBody := make([]byte, 0)
	outDomainMapMutex.RUnlock()
	if ok {
		splits := strings.SplitN(outSetting, ":", 2)
		outType = splits[0]
		outServer = splits[1]
		if strings.Contains(outServer, "remote") {
			remoteHost := strings.Split(request.RemoteAddr, ":")[0]
			outServer = strings.Replace(outServer, "remote", remoteHost, 1)
		}

		reqBody, _ := ioutil.ReadAll(request.Body)
		o := out{
			Method:         request.Method,
			Uri:            request.Host + request.RequestURI,
			RequestHeader:  request.Header,
			RequestBody:    string(reqBody),
			ResponseHeader: response.Header,
			ResponseBody:   string(body),
		}
		outBody, _ = json.Marshal(o)
	}

	return outType, outServer, outBody
}

func proxy(res *http.Response, writer http.ResponseWriter, request *http.Request) error {
	h := writer.Header()
	for k, vv := range res.Header {
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
	body, err := ghttpclient.ReadBodyClose(res)
	if err != nil {
		return errors.New("read body err: " + err.Error())
	}
	outType, outServer, outBody := outPrepare(request, res, body)
	switch outType {
	case "chan":
		body, err = ghttpclient.PostJson("http://"+outServer+"/chan", outBody, nil).ReadBodyClose()
		if err != nil {
			log.Println(err)
		}
	case "log":
		go ghttpclient.PostJson("http://"+outServer+"/log", outBody, nil).ReadBodyClose()
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	writer.WriteHeader(res.StatusCode)
	_, err = writer.Write(body)
	return err
}

func pass(res *http.Response, writer http.ResponseWriter, request *http.Request) error {
	outType, outServer, outBody := outPrepare(request, res, nil)
	switch outType {
	case "log":
		go ghttpclient.PostJson("http://"+outServer+"/log", outBody, nil).ReadBodyClose()
	}
	defer res.Body.Close()
	h := writer.Header()
	for k, vv := range res.Header {
		for _, v := range vv {
			h.Set(k, v)
		}
	}
	writer.WriteHeader(res.StatusCode)

	buf := make([]byte, 32*1024)
	for {
		n, err := res.Body.Read(buf)
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
	splits := strings.Split(request.RequestURI, "/")
	if len(splits) == 3 {
		domain := splits[1]
		outType := splits[2]
		outDomainMapMutex.Lock()
		switch outType {
		case "none":
			delete(outDomainMap, domain)
		default:
			outDomainMap[domain] = outType
		}
		outDomainMapMutex.Unlock()
		writer.Write([]byte("set " + domain + " : " + outType))
	}
}
