package archive

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"
)

// OTX lists the URLs AlienVault OTX knows of a host. It has no digests
// and no capture times: its files are fetched through the Wayback, by URL.
type OTX struct {
	Base   string // https://otx.alienvault.com
	Client *Client
	Budget *Budget
}

// Page lists one page (from 1); more says another follows.
func (o *OTX) Page(ctx context.Context, host string, page int) (caps []Capture, more bool, err error) {
	u := fmt.Sprintf("%s/api/v1/indicators/%s/%s/url_list?limit=500&page=%d", o.Base, otxSection(host), url.PathEscape(host), page)
	a, err := o.Client.GetIndex(ctx, o.Budget, u, 64<<20)
	if err != nil {
		return nil, false, err
	}
	if a.Status != 200 {
		return nil, false, fmt.Errorf("OTX: %d %s", a.Status, head(a.Body, 200))
	}
	var r struct {
		URLs []struct {
			URL      string `json:"url"`
			Date     string `json:"date"`
			HTTPCode int    `json:"httpcode"`
		} `json:"url_list"`
		HasNext bool `json:"has_next"`
	}
	if err := json.Unmarshal(a.Body, &r); err != nil {
		return nil, false, fmt.Errorf("OTX: %w", err)
	}
	for _, x := range r.URLs {
		c := Capture{URL: Normalize(x.URL), Source: "otx"}
		if x.HTTPCode != 0 {
			c.Status = fmt.Sprint(x.HTTPCode)
		}
		c.Time, _ = time.Parse("2006-01-02T15:04:05", x.Date)
		caps = append(caps, c)
	}
	return caps, r.HasNext, nil
}

// otxSection is the kind of indicator OTX files a host under (ARC-02): its
// domain section answers a registrable domain (example.com, with its
// subdomains), and an empty list for a subdomain, which is a hostname's.
func otxSection(host string) string {
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		if ip.To4() != nil {
			return "IPv4"
		}
		return "IPv6"
	}
	if rdn, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil && !strings.EqualFold(rdn, host) {
		return "hostname"
	}
	return "domain"
}
