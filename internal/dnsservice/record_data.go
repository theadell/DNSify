package dnsservice

import "fmt"

// RecordData represents the data associated with a DNS resource record.
// It provides methods to access the type, value, and the string representation of the record as per RFC 1035
type RecordData interface {
	// RecordType returns the DNS Resource Record Type.
	// This method corresponds to the TYPE field in DNS resource records as defined in the RFCs.
	// It indicates the type of the record (e.g., "A" for address records, "MX" for mail exchange records).
	RecordType() string

	// Value returns the raw data of the DNS record, known as RDATA (Resource Record Data).
	// This method corresponds to the RDATA field in DNS resource records.
	// The format and content of this value vary depending on the RecordType.
	// For example, for an "A" record, it returns the IPv4 address as a string.
	Value() string

	// String returns the full string representation of the DNS record.
	// This representation typically includes the domain name, TTL, record class (usually "IN" for internet),
	// RecordType, and the Value (RDATA).
	// This method is useful for generating the complete record string for DNS operations,
	// like constructing DNS query responses or zone file entries.
	String() string
}

// ARecord represents a DNS A record which maps a domain name to an IPv4 address.
type ARecord struct {
	IP string
}

func (a *ARecord) RecordType() string {
	return "A"
}
func (a *ARecord) String() string {
	return fmt.Sprintf("A %s", a.IP)
}
func (a *ARecord) Value() string {
	return a.IP
}

// AAAARecord represents a DNS AAAA record which maps a domain name to an IPv6 address.
type AAAARecord struct {
	IPv6 string
}

func (aaaa *AAAARecord) RecordType() string {
	return "AAAA"
}
func (aaaa *AAAARecord) Value() string {
	return aaaa.IPv6
}
func (aaaa *AAAARecord) String() string {
	return fmt.Sprintf("AAAA %s", aaaa.IPv6)
}

// CNAMERecord represents a DNS CNAME record, specifying that a domain name is an alias for another domain.
type CNAMERecord struct {
	Alias string
}

func (cname *CNAMERecord) RecordType() string {
	return "CNAME"
}

func (cname *CNAMERecord) Value() string {
	return cname.Alias
}

func (cname *CNAMERecord) String() string {
	return fmt.Sprintf("CNAME %s", cname.Alias)
}

// MXRecord represents a DNS MX record, specifying a mail server for a domain and its priority.
type MXRecord struct {
	Priority   uint16
	MailServer string
}

func (mx *MXRecord) RecordType() string {
	return "MX"
}

func (mx *MXRecord) Value() string {
	return fmt.Sprintf("%d %s", mx.Priority, mx.MailServer)
}

func (mx *MXRecord) String() string {
	return fmt.Sprintf("MX %d %s", mx.Priority, mx.MailServer)
}

// TXTRecord represents a DNS TXT record, containing text information associated with a domain.
// It often includes data for various verification purposes, such as SPF data or other metadata.
type TXTRecord struct {
	Text string
}

func (txt *TXTRecord) RecordType() string {
	return "TXT"
}

func (txt *TXTRecord) Value() string {
	return txt.Text
}

func (txt *TXTRecord) String() string {
	return fmt.Sprintf("TXT \"%s\"", txt.Text)
}

// NSRecord represents a DNS NS record, identifying the authoritative name servers for the domain.
type NSRecord struct {
	NameServer string
}

func (ns *NSRecord) RecordType() string {
	return "NS"
}

func (ns *NSRecord) Value() string {
	return ns.NameServer
}

func (ns *NSRecord) String() string {
	return fmt.Sprintf("NS %s", ns.NameServer)
}

// SRVRecord represents a DNS SRV record, which specifies the location of servers for specific services.
// It includes a target domain name, port number, and priority and weight for load balancing.
type SRVRecord struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}

func (srv *SRVRecord) RecordType() string {
	return "SRV"
}

func (srv *SRVRecord) Value() string {
	return fmt.Sprintf("%d %d %d %s", srv.Priority, srv.Weight, srv.Port, srv.Target)
}
func (srv *SRVRecord) String() string {
	return fmt.Sprintf("SRV %d %d %d %s", srv.Priority, srv.Weight, srv.Port, srv.Target)
}
