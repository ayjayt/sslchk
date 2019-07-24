// sslchk is a package to help you print out information about certificates
package sslchk

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/ayjayt/ilog"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

var defaultLogger ilog.LoggerInterface

func init() {
	if defaultLogger == nil {
		defaultLogger = &ilog.ZapWrap{Sugar: false}
		defaultLogger.Init()
	}
}

func CutString(input string) string {
	if len(input) < 15 {
		return input
	}
	return input[0:15] + "..."
}

type CheckReturn struct {
	Host     string
	IP       string
	CA       string
	Serial   string
	Issuer   string
	Subject  string
	DNS      string
	TimeLeft string
}

func (c *CheckReturn) Out() {
	w := tabwriter.NewWriter(os.Stdout, 20, 2, 2, '.', tabwriter.Debug)
	fmt.Fprintln(w, CutString(c.Host)+"\t"+CutString(c.IP)+"\t"+CutString(c.CA)+"\t"+CutString(c.Serial)+"\t"+CutString(c.Issuer)+"\t"+CutString(c.Subject)+"\t"+CutString(c.DNS)+"\t"+CutString(c.TimeLeft)+"\t")
	w.Flush()
}

func CheckHost(host string) (map[string]CheckReturn, error) {
	// get ip
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", host), nil)
	certs := make(map[string]CheckReturn, len(conn.ConnectionState().PeerCertificates))
	if err != nil {
		return nil, err
	}
	for _, chain := range conn.ConnectionState().VerifiedChains {
		for _, cert := range chain {
			sig := base64.StdEncoding.EncodeToString(cert.Signature)
			if _, ok := certs[sig]; ok {
				continue
			}

			certs[sig] = CheckReturn{
				Host:     host,
				IP:       conn.RemoteAddr().String(),
				CA:       strconv.FormatBool(cert.IsCA),
				Serial:   cert.SerialNumber.String(),
				Issuer:   string(cert.Issuer.CommonName),
				Subject:  string(cert.Subject.CommonName),
				DNS:      strings.Join(cert.DNSNames, ","),
				TimeLeft: fmt.Sprintf("%d days", cert.NotAfter.Sub(time.Now()).Round(time.Hour)/(24*time.Hour)),
			}
		}
	}

	defer conn.Close()
	return certs, nil
}

/*
func main() {
	res, err := CheckHost("google.com")
	if err != nil {
		defaultLogger.Error(err.Error())
		return
	}
	fmt.Printf("%v, %T\n", len(res), res)
	for _, v := range res {
		//fmt.Printf("%v\n\t", k)
		v.Out()
	}
	return
}
*/
