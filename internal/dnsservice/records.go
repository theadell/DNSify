package dnsservice

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var (
	ErrImmutableRecord = errors.New("attempted to modify an immutable record")
	ErrNotAuthorized   = errors.New("not authorized to perform this action")
	ErrRecordCreation  = errors.New("failed to create record")
	ErrRecordDeletion  = errors.New("failed to delete record")
)

// Record represents a DNS resource record as defined in RFC 1035.
type Record struct {

	// Name specifies the domain name of the DNS record.
	Name string

	// TTL (Time To Live) indicates the duration in seconds that the record may be cached.
	// It corresponds to the TTL field in DNS resource records.
	TTL uint

	// Data holds the specific data associated with the DNS record (such as an IP address for A records).
	// It is an implementation of the RecordData interface, providing access to the record's type, value, and string representation.
	Data RecordData

	// Hash is a unique identifier for the record, typically used for efficient lookups and comparisons.
	Hash string
}

// String returns the standard string representation of the DNS record in a format typically used in DNS zone files.
func (r Record) String() string {
	class := "IN"
	return fmt.Sprintf("%s %d %s %s", r.Name, r.TTL, class, r.Data.String())
}

func NewRecord(fqdn string, ttl uint, data RecordData) Record {
	r := Record{
		Name: fqdn,
		TTL:  ttl,
		Data: data,
	}
	r.Hash = hashRecord(r)
	return r
}

// NewRecordFromRaw constructs a Record from raw string inputs. It takes the DNS record type,
// hostname, record-specific data, TTL as a string, and the DNS zone, performing necessary
// validation and parsing. Returns a new Record and an error if the inputs are invalid.
// For MX records, 'value' should be in the "priority:mailserver" format.
// For SRV records, 'value' should be in the "priority:weight:port:target" format.
func NewRecordFromRaw(recordType, hostname, value, ttlStr, zone string) (*Record, error) {
	ttl, err := strconv.ParseUint(ttlStr, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid TTL: %s", ttlStr)
	}

	fqdn := toFQDN(hostname, zone)

	var recordData RecordData
	switch recordType {
	case "A":
		err = validateARecord(value)
		if err != nil {
			return nil, err
		}
		recordData = &ARecord{IP: value}
	case "AAAA":
		err = validateAAAARecord(value)
		if err != nil {
			return nil, err
		}
		recordData = &AAAARecord{IPv6: value}
	case "MX":
		err = validateMXRecord(value)
		if err != nil {
			return nil, err
		}
		parts := strings.Split(value, ":")
		priority, _ := strconv.Atoi(parts[0]) // Already validated
		recordData = &MXRecord{Priority: uint16(priority), MailServer: parts[1]}
	case "NS":
		err = validateNSRecord(value)
		if err != nil {
			return nil, err
		}
		recordData = &NSRecord{NameServer: value}

	case "CNAME":
		err = validateCNAMERecord(value)
		if err != nil {
			return nil, err
		}
		recordData = &CNAMERecord{Alias: value}

	case "TXT":
		err = validateTXTRecord(value)
		if err != nil {
			return nil, err
		}
		recordData = &TXTRecord{Text: value}
	case "SRV":
		err = validateSRVRecord(value)
		if err != nil {
			return nil, err
		}
		parts := strings.Split(value, ":")
		if len(parts) != 4 {
			return nil, fmt.Errorf("invalid SRV record format")
		}
		priority, _ := strconv.Atoi(parts[0]) // Assuming validation checks these
		weight, _ := strconv.Atoi(parts[1])
		port, _ := strconv.Atoi(parts[2])
		recordData = &SRVRecord{
			Priority: uint16(priority),
			Weight:   uint16(weight),
			Port:     uint16(port),
			Target:   parts[3],
		}
	default:
		return nil, fmt.Errorf("unsupported record type: %s", recordType)
	}

	r := NewRecord(fqdn, uint(ttl), recordData)
	return &r, nil
}
