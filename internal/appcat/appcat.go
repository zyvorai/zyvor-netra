// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

// Package appcat labels destinations with coarse app/category tags from
// hostname metadata (SNI / HTTP Host / DNS). Heuristic only — not DPI,
// not a 10k-app signature database.
package appcat

import (
	"strings"

	"github.com/zyvorai/netra/internal/models"
)

// Category is a coarse bucket.
type Category string

const (
	CatCDN     Category = "cdn"
	CatSaaS    Category = "saas"
	CatCloud   Category = "cloud"
	CatSocial  Category = "social"
	CatDev     Category = "devtools"
	CatFinance Category = "finance"
	CatOther   Category = "other"
)

// Entry is one hostname-suffix → category mapping.
type Entry struct {
	Suffix   string   `json:"suffix"`
	Category Category `json:"category"`
	Label    string   `json:"label"`
}

// DefaultCatalog is a small heuristic list (CDN / SaaS / cloud buckets).
func DefaultCatalog() []Entry {
	return []Entry{
		{Suffix: "cloudfront.net", Category: CatCDN, Label: "CloudFront"},
		{Suffix: "akamai.net", Category: CatCDN, Label: "Akamai"},
		{Suffix: "akamaiedge.net", Category: CatCDN, Label: "Akamai"},
		{Suffix: "fastly.net", Category: CatCDN, Label: "Fastly"},
		{Suffix: "cdn.cloudflare.net", Category: CatCDN, Label: "Cloudflare CDN"},
		{Suffix: "cloudflare.com", Category: CatCDN, Label: "Cloudflare"},
		{Suffix: "edgekey.net", Category: CatCDN, Label: "Akamai Edge"},
		{Suffix: "azureedge.net", Category: CatCDN, Label: "Azure CDN"},
		{Suffix: "trafficmanager.net", Category: CatCloud, Label: "Azure Traffic Manager"},
		{Suffix: "amazonaws.com", Category: CatCloud, Label: "AWS"},
		{Suffix: "s3.amazonaws.com", Category: CatCloud, Label: "AWS S3"},
		{Suffix: "awsglobalaccelerator.com", Category: CatCloud, Label: "AWS Global Accelerator"},
		{Suffix: "googleapis.com", Category: CatCloud, Label: "Google APIs"},
		{Suffix: "gstatic.com", Category: CatCDN, Label: "Google Static"},
		{Suffix: "googleusercontent.com", Category: CatCloud, Label: "Google User Content"},
		{Suffix: "azure.com", Category: CatCloud, Label: "Azure"},
		{Suffix: "windows.net", Category: CatCloud, Label: "Azure"},
		{Suffix: "office.com", Category: CatSaaS, Label: "Microsoft 365"},
		{Suffix: "office365.com", Category: CatSaaS, Label: "Microsoft 365"},
		{Suffix: "sharepoint.com", Category: CatSaaS, Label: "SharePoint"},
		{Suffix: "salesforce.com", Category: CatSaaS, Label: "Salesforce"},
		{Suffix: "force.com", Category: CatSaaS, Label: "Salesforce"},
		{Suffix: "slack.com", Category: CatSaaS, Label: "Slack"},
		{Suffix: "atlassian.net", Category: CatSaaS, Label: "Atlassian"},
		{Suffix: "jira.com", Category: CatSaaS, Label: "Jira"},
		{Suffix: "github.com", Category: CatDev, Label: "GitHub"},
		{Suffix: "githubusercontent.com", Category: CatDev, Label: "GitHub"},
		{Suffix: "gitlab.com", Category: CatDev, Label: "GitLab"},
		{Suffix: "bitbucket.org", Category: CatDev, Label: "Bitbucket"},
		{Suffix: "docker.com", Category: CatDev, Label: "Docker"},
		{Suffix: "docker.io", Category: CatDev, Label: "Docker Hub"},
		{Suffix: "npmjs.org", Category: CatDev, Label: "npm"},
		{Suffix: "pypi.org", Category: CatDev, Label: "PyPI"},
		{Suffix: "stripe.com", Category: CatFinance, Label: "Stripe"},
		{Suffix: "paypal.com", Category: CatFinance, Label: "PayPal"},
		{Suffix: "facebook.com", Category: CatSocial, Label: "Meta"},
		{Suffix: "fbcdn.net", Category: CatCDN, Label: "Meta CDN"},
		{Suffix: "twitter.com", Category: CatSocial, Label: "X/Twitter"},
		{Suffix: "twimg.com", Category: CatCDN, Label: "Twitter CDN"},
		{Suffix: "linkedin.com", Category: CatSocial, Label: "LinkedIn"},
		{Suffix: "zoom.us", Category: CatSaaS, Label: "Zoom"},
		{Suffix: "okta.com", Category: CatSaaS, Label: "Okta"},
		{Suffix: "auth0.com", Category: CatSaaS, Label: "Auth0"},
		{Suffix: "servicenow.com", Category: CatSaaS, Label: "ServiceNow"},
		{Suffix: "workday.com", Category: CatSaaS, Label: "Workday"},
		{Suffix: "box.com", Category: CatSaaS, Label: "Box"},
		{Suffix: "dropbox.com", Category: CatSaaS, Label: "Dropbox"},
		{Suffix: "notion.so", Category: CatSaaS, Label: "Notion"},
		{Suffix: "figma.com", Category: CatDev, Label: "Figma"},
		{Suffix: "datadoghq.com", Category: CatDev, Label: "Datadog"},
		{Suffix: "splunkcloud.com", Category: CatDev, Label: "Splunk"},
		{Suffix: "grafana.com", Category: CatDev, Label: "Grafana"},
		{Suffix: "openai.com", Category: CatSaaS, Label: "OpenAI"},
		{Suffix: "anthropic.com", Category: CatSaaS, Label: "Anthropic"},
		{Suffix: "discord.com", Category: CatSocial, Label: "Discord"},
		{Suffix: "reddit.com", Category: CatSocial, Label: "Reddit"},
		{Suffix: "tiktok.com", Category: CatSocial, Label: "TikTok"},
		{Suffix: "instagram.com", Category: CatSocial, Label: "Instagram"},
		{Suffix: "coinbase.com", Category: CatFinance, Label: "Coinbase"},
		{Suffix: "binance.com", Category: CatFinance, Label: "Binance"},
		{Suffix: "digitalocean.com", Category: CatCloud, Label: "DigitalOcean"},
		{Suffix: "heroku.com", Category: CatCloud, Label: "Heroku"},
		{Suffix: "vercel.com", Category: CatCloud, Label: "Vercel"},
		{Suffix: "netlify.com", Category: CatCloud, Label: "Netlify"},
		{Suffix: "cloudflare-dns.com", Category: CatCDN, Label: "Cloudflare DNS"},
		{Suffix: "fastly-insights.com", Category: CatCDN, Label: "Fastly Insights"},
		{Suffix: "jsdelivr.net", Category: CatCDN, Label: "jsDelivr"},
		{Suffix: "unpkg.com", Category: CatCDN, Label: "unpkg"},
		{Suffix: "cdn.jsdelivr.net", Category: CatCDN, Label: "jsDelivr CDN"},
		{Suffix: "google.com", Category: CatCloud, Label: "Google"},
		{Suffix: "withgoogle.com", Category: CatCloud, Label: "Google"},
		{Suffix: "oraclecloud.com", Category: CatCloud, Label: "Oracle Cloud"},
		{Suffix: "oci.oraclecloud.com", Category: CatCloud, Label: "Oracle OCI"},
		{Suffix: "linode.com", Category: CatCloud, Label: "Linode/Akamai"},
		{Suffix: "vultr.com", Category: CatCloud, Label: "Vultr"},
		{Suffix: "hetzner.com", Category: CatCloud, Label: "Hetzner"},
		{Suffix: "ovh.net", Category: CatCloud, Label: "OVH"},
		{Suffix: "teams.microsoft.com", Category: CatSaaS, Label: "Microsoft Teams"},
		{Suffix: "webex.com", Category: CatSaaS, Label: "Webex"},
		{Suffix: "cisco.com", Category: CatSaaS, Label: "Cisco"},
		{Suffix: "zendesk.com", Category: CatSaaS, Label: "Zendesk"},
		{Suffix: "intercom.io", Category: CatSaaS, Label: "Intercom"},
		{Suffix: "hubspot.com", Category: CatSaaS, Label: "HubSpot"},
		{Suffix: "shopify.com", Category: CatSaaS, Label: "Shopify"},
		{Suffix: "myshopify.com", Category: CatSaaS, Label: "Shopify"},
		{Suffix: "twilio.com", Category: CatSaaS, Label: "Twilio"},
		{Suffix: "sendgrid.net", Category: CatSaaS, Label: "SendGrid"},
		{Suffix: "mailgun.org", Category: CatSaaS, Label: "Mailgun"},
		{Suffix: "pagerduty.com", Category: CatDev, Label: "PagerDuty"},
		{Suffix: "opsgenie.com", Category: CatDev, Label: "Opsgenie"},
		{Suffix: "newrelic.com", Category: CatDev, Label: "New Relic"},
		{Suffix: "sentry.io", Category: CatDev, Label: "Sentry"},
		{Suffix: "launchdarkly.com", Category: CatDev, Label: "LaunchDarkly"},
		{Suffix: "segment.com", Category: CatDev, Label: "Segment"},
		{Suffix: "segment.io", Category: CatDev, Label: "Segment"},
		{Suffix: "mixpanel.com", Category: CatDev, Label: "Mixpanel"},
		{Suffix: "amplitude.com", Category: CatDev, Label: "Amplitude"},
		{Suffix: "circleci.com", Category: CatDev, Label: "CircleCI"},
		{Suffix: "travis-ci.com", Category: CatDev, Label: "Travis CI"},
		{Suffix: "buildkite.com", Category: CatDev, Label: "Buildkite"},
		{Suffix: "sonarcloud.io", Category: CatDev, Label: "SonarCloud"},
		{Suffix: "whatsapp.com", Category: CatSocial, Label: "WhatsApp"},
		{Suffix: "telegram.org", Category: CatSocial, Label: "Telegram"},
		{Suffix: "snapchat.com", Category: CatSocial, Label: "Snapchat"},
		{Suffix: "pinterest.com", Category: CatSocial, Label: "Pinterest"},
		{Suffix: "plaid.com", Category: CatFinance, Label: "Plaid"},
		{Suffix: "adyen.com", Category: CatFinance, Label: "Adyen"},
		{Suffix: "braintreegateway.com", Category: CatFinance, Label: "Braintree"},
		{Suffix: "square.com", Category: CatFinance, Label: "Square"},
		{Suffix: "squareup.com", Category: CatFinance, Label: "Square"},
		{Suffix: "kraken.com", Category: CatFinance, Label: "Kraken"},
		{Suffix: "cloudflare-ipfs.com", Category: CatCDN, Label: "Cloudflare IPFS"},
		{Suffix: "bunnycdn.com", Category: CatCDN, Label: "BunnyCDN"},
		{Suffix: "b-cdn.net", Category: CatCDN, Label: "BunnyCDN"},
		{Suffix: "stackpathdns.com", Category: CatCDN, Label: "StackPath"},
		{Suffix: "asana.com", Category: CatSaaS, Label: "Asana"},
		{Suffix: "monday.com", Category: CatSaaS, Label: "Monday"},
		{Suffix: "airtable.com", Category: CatSaaS, Label: "Airtable"},
		{Suffix: "miro.com", Category: CatSaaS, Label: "Miro"},
		{Suffix: "lucidchart.com", Category: CatSaaS, Label: "Lucidchart"},
		{Suffix: "crates.io", Category: CatDev, Label: "crates.io"},
		{Suffix: "pkg.go.dev", Category: CatDev, Label: "pkg.go.dev"},
		{Suffix: "rubygems.org", Category: CatDev, Label: "RubyGems"},
		{Suffix: "nuget.org", Category: CatDev, Label: "NuGet"},
		{Suffix: "maven.org", Category: CatDev, Label: "Maven"},
		{Suffix: "cloud.google.com", Category: CatCloud, Label: "Google Cloud"},
		{Suffix: "run.app", Category: CatCloud, Label: "Cloud Run"},
		{Suffix: "azurewebsites.net", Category: CatCloud, Label: "Azure App Service"},
		{Suffix: "cloudapp.azure.com", Category: CatCloud, Label: "Azure Cloud App"},
		{Suffix: "wise.com", Category: CatFinance, Label: "Wise"},
		{Suffix: "checkout.com", Category: CatFinance, Label: "Checkout.com"},
		{Suffix: "klarna.com", Category: CatFinance, Label: "Klarna"},
		{Suffix: "threads.net", Category: CatSocial, Label: "Threads"},
		{Suffix: "mastodon.social", Category: CatSocial, Label: "Mastodon"},
	}
}

// Hit is one labeled destination observation.
type Hit struct {
	Category  Category `json:"category"`
	Label     string   `json:"label"`
	Host      string   `json:"host"`
	Kind      string   `json:"kind"`
	Node      string   `json:"node,omitempty"`
	Namespace string   `json:"namespace,omitempty"`
	Pod       string   `json:"pod,omitempty"`
	Packets   uint64   `json:"packets,omitempty"`
}

// Result is the API envelope.
type Result struct {
	Hits       []Hit            `json:"hits"`
	Count      int              `json:"count"`
	ByCategory map[Category]int `json:"byCategory"`
	Capped     bool             `json:"capped"`
	Catalog    int              `json:"catalogSize"`
	Note       string           `json:"note"`
}

const MaxHits = 500

// Match labels agent TLS/HTTP/DNS metadata against the catalog.
func Match(agents []models.AgentStatus, catalog []Entry, limit int) Result {
	if limit <= 0 || limit > MaxHits {
		limit = MaxHits
	}
	if len(catalog) == 0 {
		catalog = DefaultCatalog()
	}
	out := Result{
		Hits: []Hit{}, Catalog: len(catalog), ByCategory: map[Category]int{},
		Note: "Heuristic hostname categories from metadata only — not DPI / app signatures.",
	}
	add := func(host, kind, node, ns, pod string, pkts uint64) {
		if len(out.Hits) >= limit {
			out.Capped = true
			return
		}
		e, ok := lookup(catalog, host)
		if !ok {
			return
		}
		out.Hits = append(out.Hits, Hit{
			Category: e.Category, Label: e.Label, Host: host, Kind: kind,
			Node: node, Namespace: ns, Pod: pod, Packets: pkts,
		})
		out.ByCategory[e.Category]++
	}
	for _, a := range agents {
		if a.Stale {
			continue
		}
		for _, t := range a.TLSMetadata {
			add(t.SNI, "sni", a.Node, t.Namespace, t.Pod, t.Handshakes)
		}
		for _, h := range a.HTTPMetadata {
			add(h.Host, "http-host", a.Node, h.Namespace, h.Pod, h.Requests)
		}
		for _, d := range a.DNSHealth {
			add(d.Name, "dns", a.Node, d.Namespace, d.Pod, d.Queries)
		}
	}
	out.Count = len(out.Hits)
	return out
}

func lookup(catalog []Entry, host string) (Entry, bool) {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return Entry{}, false
	}
	var best Entry
	bestLen := -1
	for _, e := range catalog {
		suf := strings.ToLower(strings.TrimSuffix(e.Suffix, "."))
		if h == suf || strings.HasSuffix(h, "."+suf) {
			if len(suf) > bestLen {
				best = e
				bestLen = len(suf)
			}
		}
	}
	if bestLen < 0 {
		return Entry{}, false
	}
	return best, true
}

// Lookup returns the best catalog match for host (longest suffix).
func Lookup(host string) (Entry, bool) {
	return lookup(DefaultCatalog(), host)
}

// MatchHostSuffix reports whether host matches any sanctioned suffix.
func MatchHostSuffix(host string, suffixes []string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return false
	}
	for _, s := range suffixes {
		suf := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
		if suf == "" {
			continue
		}
		if h == suf || strings.HasSuffix(h, "."+suf) {
			return true
		}
	}
	return false
}
