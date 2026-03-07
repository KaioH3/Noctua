package intel

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type OTX struct {
	apiKey string
	client *http.Client
}

func NewOTX(apiKey string) *OTX {
	return &OTX{
		apiKey: apiKey,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (o *OTX) Name() string { return "otx" }

func (o *OTX) CheckIP(ip string) (map[string]any, error) {
	if o.apiKey == "" {
		return nil, fmt.Errorf("no OTX API key configured")
	}

	reqURL := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/IPv4/%s/general", ip)
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-OTX-API-KEY", o.apiKey)

	resp, err := o.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("otx: status %d", resp.StatusCode)
	}

	var result struct {
		PulseInfo struct {
			Count  int `json:"count"`
			Pulses []struct {
				Name string   `json:"name"`
				Tags []string `json:"tags"`
			} `json:"pulses"`
		} `json:"pulse_info"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var pulseNames []string
	var allTags []string
	for _, p := range result.PulseInfo.Pulses {
		pulseNames = append(pulseNames, p.Name)
		allTags = append(allTags, p.Tags...)
	}

	return map[string]any{
		"pulse_count": result.PulseInfo.Count,
		"pulses":      pulseNames,
		"tags":        allTags,
	}, nil
}
