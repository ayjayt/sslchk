// sslchk is a package to help you print out information about certificates
package sslchk

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ayjayt/ilog"
)

var defaultLogger ilog.LoggerInterface

func init() {
	if defaultLogger == nil {
		defaultLogger = &ilog.ZapWrap{Sugar: false}
		defaultLogger.Init()
	}
}

var minWidth = 15

func CutString(input string) string {
	if len(input) < minWidth-1 {
		return input
	}
	return input[0:minWidth-4] + "..."
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
	w := tabwriter.NewWriter(os.Stdout, minWidth, 1, 1, '.', tabwriter.Debug)
	fmt.Fprintln(w, CutString(c.Host)+"\t"+CutString(c.IP)+"\t"+CutString(c.CA)+"\t"+CutString(c.Serial)+"\t"+CutString(c.Issuer)+"\t"+CutString(c.Subject)+"\t"+CutString(c.TimeLeft)+"\t")
	w.Flush()
}

func CheckHost(host string) (map[string]CheckReturn, error) {
	dialer := net.Dialer{Timeout: 1 * time.Second}
	conn, err := tls.DialWithDialer(&dialer, "tcp", fmt.Sprintf("%s:443", host), nil)
	if err != nil {
		return nil, err
	}
	if conn.ConnectionState().PeerCertificates == nil || conn.ConnectionState().VerifiedChains == nil {
		return nil, errors.New("No certificates")
	}
	certs := make(map[string]CheckReturn, len(conn.ConnectionState().PeerCertificates))
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
