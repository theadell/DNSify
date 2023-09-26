package dnsutils

import (
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/miekg/dns"
)

type Record struct {
	Type string
	FQDN string
	IP   string
	TTL  uint
}

// application start > parse > watch > on change > parse
func ReadRecords(zoneFilePath string) ([]Record, error) {
	zoneFile, err := os.Open(zoneFilePath)
	if err != nil {
		log.Println("Failed to open zone file")
		return nil, err
	}
	defer zoneFile.Close()
	records := make([]Record, 0)
	zp := dns.NewZoneParser(zoneFile, "", zoneFilePath)

	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if rr == nil {
			continue // Possibly a directive line like $TTL, or a comment line.
		}
		switch record := rr.(type) {
		case *dns.A:
			nr := Record{Type: "A", FQDN: record.Hdr.Name, IP: record.A.String(), TTL: uint(record.Hdr.Ttl)}
			records = append(records, nr)
		}
	}

	if err := zp.Err(); err != nil {
		return nil, err
	}
	return records, nil

}

func InsertRecordSync(client *dns.Client, keyName string, record Record) error {

	domain := "rusty-leipzig.com."

	server := "157.230.106.145:53"

	m := new(dns.Msg)
	// Set the zone that you are updating.
	m.SetUpdate(domain)

	// Create a new Resource Record (RR) for adding the A record.
	// A Resource Record (RR) contains the information associated with the domain such as its IP address.
	rr, err := dns.NewRR(fmt.Sprintf("%s A %s", record.FQDN, record.IP))
	if err != nil {
		return err
	}

	// Insert the Resource Record to the message.
	m.Insert([]dns.RR{rr})

	m.SetTsig(keyName, dns.HmacSHA256, 300, time.Now().Unix())

	r, _, err := client.Exchange(m, server)
	if err != nil {
		return err
	}

	if r.Rcode != dns.RcodeSuccess {
		return errors.New(fmt.Sprintf("Failed top update record with status code %d\n", r.Rcode))
	}
	log.Println("Added Record Successfully")
	return nil
}
