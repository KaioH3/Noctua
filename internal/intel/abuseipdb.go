package intel

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type AbuseIPDB struct {
	apiKey string
	client *http.Client
}

func NewAbuseIPDB(apiKey string) *AbuseIPDB {
	return &AbuseIPDB{
		apiKey: apiKey,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (a *AbuseIPDB) Name() string { return "abuseipdb" }

func (a *AbuseIPDB) CheckIP(ip string) (map[string]any, error) {
	if a.apiKey == "" {
		return nil, fmt.Errorf("no API key configured")
	}

	req, err := http.NewRequest("GET", "https://api.abuseipdb.com/api/v2/check", nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Set("ipAddress", ip)
	q.Set("maxAgeInDays", "90")
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Key", a.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("abuseipdb: status %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			CountryCode          string `json:"countryCode"`
			TotalReports         int    `json:"totalReports"`
			IsWhitelisted        bool   `json:"isWhitelisted"`
			ISP                  string `json:"isp"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return map[string]any{
		"abuse_score":    float64(result.Data.AbuseConfidenceScore),
		"country":        result.Data.CountryCode,
		"total_reports":  result.Data.TotalReports,
		"is_whitelisted": result.Data.IsWhitelisted,
		"isp":            result.Data.ISP,
	}, nil
}
