// Package digitalocean implements a DNS provider for solving the DNS-01
// challenge using InternetX DNS.
package internetx

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/xenolf/lego/acme"
)

var apiURL = "https://gateway.autodns.com"

// DNSProvider is an implementation of the acme.ChallengeProvider interface
// that uses InterNetX API to manage TXT records for a domain.
type DNSProvider struct {
	apiUser     string
	apiPassword string
	apiContext  string
}

type APIAuthNode struct {
	User     string `xml:"user"`
	Password string `xml:"password"`
	Context  string `xml:"context"`
}

type APIRRNode struct {
	Name string `xml:"name"`
	Type string `xml:"type"`
	//TTL   int    `xml:"ttl"`
	Value string `xml:"value"`
}

type APISOANode struct {
	Level int `xml:"level"`
}

type APIZoneNode struct {
	Name string `xml:"name"`
	//SystemNS   string  `xml:"system_ns"`
	//NSAction   string  `xml:"ns_action"`
	RR         APIRRNode  `xml:"rr"`
	SOA        APISOANode `xml:"soa"`
	Key        string     `xml:"key"`
	WWWInclude int        `xml:"www_include"`
}

type APIZoneAPITaskNodeNode struct {
	Code string      `xml:"code"`
	Zone APIZoneNode `xml:"zone"`
}

type APIRequest struct {
	XMLName     xml.Name               `xml:"request"`
	Auth        APIAuthNode            `xml:"auth"`
	APITaskNode APIZoneAPITaskNodeNode `xml:"task"`
}

//type APIStatusNode struct {
//	Type string `xml:"type"`
//	Code string `xml:"code"`
//	Text string `xml:"text"`
//}
//
//type APIDataNode struct {
//	Object []string `xml:"object"`
//}
//
//type APIObjectNode struct {
//	Type  []string `xml:"type"`
//	Value []string `xml:"value"`
//}
//
//type APIMsgNode struct {
//	Text   string          `xml:"text"`
//	Object []APIObjectNode `xml:"object"`
//	Help   []string        `xml:"help"`
//}
//
//type APIResultNode struct {
//	Data   []APIDataNode `xml:"data"`
//	Status APIStatusNode `xml:"status"`
//	Msg    []APIMsgNode  `xml:"msg"`
//}
//
//type APIResponse struct {
//	XMLName xml.Name        `xml:"response"`
//	Result  []APIResultNode `xml:"result"`
//}

// NewDNSProvider returns a DNSProvider instance. Credentials must be passed in the environment variable:
// INTERNETX_USER
// INTERNETX_PASSWORD
// INTERNETX_CONTEXT
func NewDNSProvider() (*DNSProvider, error) {
	apiUser := os.Getenv("INTERNETX_USER")
	apiPassword := os.Getenv("INTERNETX_PASSWORD")
	apiContext := os.Getenv("INTERNETX_CONTEXT")
	return NewDNSProviderCredentials(apiUser, apiPassword, apiContext)
}

// NewDNSProviderCredentials uses the supplied credentials to return a
// InterNetX instance configured for Digital Ocean.
func NewDNSProviderCredentials(apiUser string, apiPassword string, apiContext string) (*DNSProvider, error) {
	if apiUser == "" || apiPassword == "" {
		return nil, fmt.Errorf("InterNetX credentials missing or incomplete")
	}
	return &DNSProvider{
		apiUser:     apiUser,
		apiPassword: apiPassword,
		apiContext:  apiContext,
	}, nil
}

// Present creates a TXT record using the specified parameters
func (d *DNSProvider) Present(domain, token, keyAuth string) error {

	fqdn, value, _ := acme.DNS01Record(domain, keyAuth)

	authZone, err := acme.FindZoneByFqdn(acme.ToFqdn(domain), acme.RecursiveNameservers)
	if err != nil {
		return fmt.Errorf("Could not determine zone for domain: '%s'. %s", domain, err)
	}

	rr := APIRRNode{Name: fqdn, Type: "TXT", Value: value}
	task := APIZoneAPITaskNodeNode{Code: "0202", Zone: APIZoneNode{Name: authZone, RR: rr, SOA: APISOANode{Level: 3}, Key: "rs_add"}}
	reqData := APIRequest{Auth: APIAuthNode{User: d.apiUser, Password: d.apiPassword, Context: d.apiContext}, APITaskNode: task}

	//Generic Reader
	type nopCloser struct {
		io.Reader
	}

	xmlString, _ := xml.MarshalIndent(reqData, "", "  ")
	log.Printf(string(xmlString))
	reqBody := nopCloser{bytes.NewBufferString(string(xmlString))}
	req, err := http.NewRequest("POST", apiURL, reqBody)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/xml; charset=utf-8")

	client := http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	//Not going to implement native objects for API server response
	//	apiResp := APIResponse{}
	//	if body, err := ioutil.ReadAll(resp.Body); err == nil {
	//		if xmlerr := xml.Unmarshal(body, &apiResp); xmlerr != nil {
	//			return xmlerr
	//		}
	//	} else {
	//		return err
	//	}

	respBody, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return err
	}

	log.Printf(string(respBody))

	return nil
}

// CleanUp removes the TXT record matching the specified parameters
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {

	fqdn, value, _ := acme.DNS01Record(domain, keyAuth)


	authZone, err := acme.FindZoneByFqdn(acme.ToFqdn(domain), acme.RecursiveNameservers)
	if err != nil {
		return fmt.Errorf("Could not determine zone for domain: '%s'. %s", domain, err)
	}

	authZone = acme.UnFqdn(authZone)

	rr := APIRRNode{Name: fqdn, Type: "TXT", Value: value}
	//rr := APIRRNode{Name: fqdn, Type: "TXT", Value: value}
	task := APIZoneAPITaskNodeNode{Code: "0202", Zone: APIZoneNode{Name: authZone, RR: rr, SOA: APISOANode{Level: 3}, Key: "rr_rem"}}
	reqData := APIRequest{Auth: APIAuthNode{User: d.apiUser, Password: d.apiPassword, Context: d.apiContext}, APITaskNode: task}

	//Generic Reader
	type nopCloser struct {
		io.Reader
	}

	xmlString, _ := xml.MarshalIndent(reqData, "", "  ")
	log.Printf(string(xmlString))
	reqBody := nopCloser{bytes.NewBufferString(string(xmlString))}
	req, err := http.NewRequest("POST", apiURL, reqBody)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/xml; charset=utf-8")

	client := http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)

	if err != nil {
		return err
	}

	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return err
	}

	log.Printf(string(respBody))

	return nil
}
