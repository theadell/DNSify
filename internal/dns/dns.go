package dns

import (
	"log"
	"os"

	"github.com/miekg/dns"
)

type Record struct {
	Type     string
	Hostname string
	Value    string
	TTL      uint
}

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
			nr := Record{Type: "A", Hostname: record.Hdr.Name, Value: record.A.String()}
			records = append(records, nr)
			log.Printf("A record, Address: %s, Name: %s\n", record.A, record.Hdr.Name)
		}
	}

	if err := zp.Err(); err != nil {
		return nil, err
	}
	return records, nil

}
