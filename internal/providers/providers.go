package providers

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/net/context/ctxhttp"
)

var SpamhausDROP = &Provider{
	url:    "https://www.spamhaus.org/drop/drop.txt",
	mapper: trimAfterAllMapper(';'),
}

var SpamhausEDROP = &Provider{
	url:    "https://www.spamhaus.org/drop/edrop.txt",
	mapper: trimAfterAllMapper(';'),
}

var EmergingThreats = &Provider{
	url:    "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
	mapper: trimAfterAllMapper('#'),
}

var Okean = &Provider{
	url:    "https://www.okean.com/sinokoreacidr.txt",
	mapper: trimAfterAllMapper('#', ' '),
}

var MyIP = &Provider{
	url:    "https://www.myip.ms/files/blacklist/general/latest_blacklist.txt",
	mapper: trimAfterAllMapper('#'),
}

var DShield = &Provider{
	url: "https://feeds.dshield.org/block.txt",
	mapper: func(line string) string {
		line = trimAfter(line, '#')

		parts := strings.Split(line, "\t")
		if len(parts) < 2 {
			return ""
		}

		if parts[0] == "Start" {
			return ""
		}

		return parts[0] + "-" + parts[1]
	},
}

type Provider struct {
	url    string
	mapper mapper
}

func (p *Provider) URL() string {
	return p.url
}

func (p *Provider) List(ctx context.Context) ([]string, error) {
	resp, err := get(ctx, p.url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return parseLines(resp.Body, p.mapper)
}

func get(ctx context.Context, url string) (*http.Response, error) {
	resp, err := ctxhttp.Get(ctx, nil, url)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status code %d", resp.StatusCode)
	}

	return resp, nil
}

type mapper func(line string) string

func parseLines(r io.Reader, mapper mapper) ([]string, error) {
	scanner := bufio.NewScanner(r)

	var lines []string

	for scanner.Scan() {
		line := scanner.Text()
		line = mapper(line)
		line = strings.TrimSpace(line)

		// Skip IPv6 rules
		if strings.ContainsRune(line, ':') {
			continue
		}

		if line != "" {
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

func trimAfterAllMapper(seps ...rune) mapper {
	return func(line string) string {
		for _, r := range seps {
			line = trimAfter(line, r)
		}
		return line
	}
}

func trimAfter(line string, r rune) string {
	if r != 0 {
		i := strings.IndexRune(line, r)
		if i >= 0 {
			line = line[:i]
		}
	}
	return strings.TrimSpace(line)
}
