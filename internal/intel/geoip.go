package intel

import (
	"fmt"
	"net"

	"github.com/oschwald/maxminddb-golang"
)

var highRiskCountries = map[string]bool{
	"KP": true, "IR": true, "RU": true, "CN": true,
	"SY": true, "CU": true, "VE": true,
}

type GeoIP struct {
	db *maxminddb.Reader
}

func NewGeoIP(dbPath string) (*GeoIP, error) {
	db, err := maxminddb.Open(dbPath)
	if err != nil {
		return nil, fmt.Errorf("geoip: opening %s: %w", dbPath, err)
	}
	return &GeoIP{db: db}, nil
}

func (g *GeoIP) Name() string { return "geoip" }

func (g *GeoIP) CheckIP(ip string) (map[string]any, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid IP: %s", ip)
	}

	var record struct {
		Country struct {
			ISOCode string            `maxminddb:"iso_code"`
			Names   map[string]string `maxminddb:"names"`
		} `maxminddb:"country"`
		City struct {
			Names map[string]string `maxminddb:"names"`
		} `maxminddb:"city"`
	}

	if err := g.db.Lookup(parsedIP, &record); err != nil {
		return nil, err
	}

	countryName := record.Country.Names["en"]
	cityName := record.City.Names["en"]

	return map[string]any{
		"country_code":     record.Country.ISOCode,
		"country":          countryName,
		"city":             cityName,
		"high_risk_country": highRiskCountries[record.Country.ISOCode],
	}, nil
}

func (g *GeoIP) Close() error {
	if g.db != nil {
		return g.db.Close()
	}
	return nil
}
