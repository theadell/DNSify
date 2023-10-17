package dnsclient

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Record struct {
	Type string
	FQDN string
	IP   string
	TTL  uint
	Hash string
}

func NewRecord(typ, fqdn, ip string, ttl uint) Record {
	r := Record{
		Type: typ,
		FQDN: fqdn,
		IP:   ip,
		TTL:  ttl,
	}
	r.Hash = hashRecord(r)
	return r
}

type DNSClient interface {
	GetRecords() []Record
	AddRecord(Record) error
	RemoveRecord(Record) error
	GetRecordByHash(string) *Record
	GetRecordForFQDN(string, string) *Record
	GetRecordByFQDNAndType(string, string) *Record
	Close()
}

type DNSClientConfig struct {
	ZoneFilePath string `mapstructure:"zoneFilePath"`
	TSIGKey      string `mapstructure:"tsigKey"`
	TSIGSecret   string `mapstructure:"tsigSecret"`
	Host         string `mapstructure:"host"`
	Port         uint16 `mapstructure:"port"`
	Zone         string `mapstructure:"zone"`
	SyncInterval int    `mapstructure:"SyncInterval"`
}

type BindClient struct {
	cache        []Record
	mutex        sync.RWMutex
	client       *dns.Client
	zone         string
	zoneFilePath string
	host         net.IP
	port         uint16
	serverAddr   string
	tsigKey      string
	SyncInterval int
	done         chan bool
}

func NewBindClient(config DNSClientConfig) (*BindClient, error) {

	hostIp := net.ParseIP(config.Host)
	if hostIp == nil || hostIp.IsUnspecified() {
		return nil, fmt.Errorf("invalid or unspecified IP address")
	}
	if config.Port == 0 {
		config.Port = 53
	}
	if config.Zone == "" {
		return nil, fmt.Errorf("zone must be specified")
	}
	if config.TSIGKey == "" || config.TSIGSecret == "" {
		return nil, fmt.Errorf("TSIGKey and TSIGSecret must be specified")
	}
	if config.SyncInterval <= 0 {
		config.SyncInterval = 30
	}

	client := &BindClient{
		cache:        make([]Record, 0),
		mutex:        sync.RWMutex{},
		client:       new(dns.Client),
		zone:         config.Zone,
		zoneFilePath: config.ZoneFilePath,
		host:         hostIp,
		port:         config.Port,
		serverAddr:   fmt.Sprintf("%s:%d", hostIp.String(), config.Port),
		tsigKey:      config.TSIGKey,
		SyncInterval: config.SyncInterval,
		done:         make(chan bool),
	}

	client.client.TsigSecret = map[string]string{config.TSIGKey: config.TSIGSecret}

	err := client.populateCache()
	if err != nil {
		return nil, err
	}
	go client.backgroundSync()
	return client, nil
}

func (c *BindClient) populateCache() error {
	recrods, err := readRecordsFromZone(c.zoneFilePath)
	if err != nil {
		return err
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.cache = recrods
	return nil
}

func (c *BindClient) GetRecords() []Record {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	recordsCopy := make([]Record, len(c.cache))
	copy(recordsCopy, c.cache)
	return recordsCopy
}

func (c *BindClient) GetRecordByHash(targetHash string) *Record {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	for _, record := range c.cache {
		if record.Hash == targetHash {
			recordCopy := record
			return &recordCopy
		}
	}
	return nil
}

func (c *BindClient) GetRecordByFQDNAndType(recordFQDN, recordType string) *Record {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	idx := slices.IndexFunc(c.cache, func(record Record) bool {
		return record.Type == recordType && record.FQDN == recordFQDN
	})
	if idx != -1 {
		recordCopy := c.cache[idx]
		return &recordCopy
	}
	return nil
}

func (c *BindClient) GetRecordForFQDN(targetFQDN, recordType string) *Record {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	for _, record := range c.cache {
		if record.Type == recordType && record.FQDN == targetFQDN {
			recordCopy := record
			return &recordCopy
		}
	}
	return nil
}
func readRecordsFromZone(zoneFilePath string) ([]Record, error) {
	zoneFile, err := os.Open(zoneFilePath)
	if err != nil {
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
		case *dns.AAAA:
			nr := Record{Type: "AAAA", FQDN: record.Hdr.Name, IP: record.AAAA.String(), TTL: uint(record.Hdr.Ttl)}
			records = append(records, nr)
		case *dns.NS:
			nr := Record{Type: "NS", FQDN: record.Hdr.Name, IP: record.Ns, TTL: uint(record.Hdr.Ttl)}
			records = append(records, nr)
		}
	}
	if err := zp.Err(); err != nil {
		return nil, err
	}
	for i := range records {
		records[i].Hash = hashRecord(records[i])
	}

	return records, nil
}

func (c *BindClient) AddRecord(record Record) error {
	slog.Debug("Attempting to add record", "record", record)
	msg := new(dns.Msg)
	msg.SetUpdate(c.zone)
	resourceRecord, err := dns.NewRR(fmt.Sprintf("%s %s %s", record.FQDN, record.Type, record.IP))
	if err != nil {
		return err
	}
	msg.Insert([]dns.RR{resourceRecord})
	msg.SetTsig(c.tsigKey, dns.HmacSHA256, 300, time.Now().Unix())
	replyMsg, _, err := c.client.Exchange(msg, c.serverAddr)
	if err != nil {
		return err
	}
	if replyMsg.Rcode != dns.RcodeSuccess {
		return errors.New(fmt.Sprintf("Failed top update record with status code %d\n", replyMsg.Rcode))
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	record.Hash = hashRecord(record)
	c.cache = append(c.cache, record)
	return nil
}

func (c *BindClient) RemoveRecord(record Record) error {

	msg := new(dns.Msg)
	msg.SetUpdate(c.zone)

	resourceRecord, err := dns.NewRR(fmt.Sprintf("%s %s %s", record.FQDN, record.Type, record.IP))
	if err != nil {
		return fmt.Errorf("failed to create Resource Record: %w", err)
	}

	msg.Remove([]dns.RR{resourceRecord})
	msg.SetTsig(c.tsigKey, dns.HmacSHA256, 300, time.Now().Unix())

	replyMsg, _, err := c.client.Exchange(msg, c.serverAddr)
	if err != nil {
		return fmt.Errorf("failed to exchange message: %w", err)
	}

	if replyMsg.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("failed to update record with status code %d", replyMsg.Rcode)
	}
	c.mutex.Lock()
	defer c.mutex.Unlock()
	for i, r := range c.cache {
		if r.FQDN == record.FQDN && r.Type == record.Type && r.IP == record.IP {
			c.cache = append(c.cache[:i], c.cache[i+1:]...)
			break
		}
	}

	return nil
}
func (c *BindClient) backgroundSync() {
	ticker := time.NewTicker(time.Duration(c.SyncInterval) * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			slog.Info("Starting sync of journal to zone file")
			err := c.syncJournalToZoneFile()
			if err != nil {
				slog.Error("Failed to sync journal to zone file", "error", err.Error())
			} else {
				err = c.populateCache()
				if err != nil {
					slog.Error("Failed to synchronize records", "error", err.Error())
				} else {
					slog.Info("Records synchronized successfully")
				}
			}
		case <-c.done:
			slog.Info("Terminating background synchronization")
			return
		}
	}
}

func (c *BindClient) Close() {
	close(c.done)
}

// fetchZoneRecords fetches the DNS zone records for a given domain from a specific DNS server using
// the AXFR (Authoritative Zone Transfer) method. The caller must provide TSIG (Transaction Signature)
// authentication details using a key and a secret. Note: For this function to work, the DNS server in question
// must have zone transfers enabled for clients that present valid TSIG keys. For instance, using BIND9 you must include
// the below directive to your configuration
// allow-transfer { key "key-name"; };
//
// Parameters:
//
// domain: The target domain name (zone), e.g., "example.com".
//
// dnsServer: The address (including port) of the DNS server to fetch the records from, e.g. "ns1.example.com:53".
//
// keyName: The name of the TSIG key used for authentication.
//
// secret: The actual secret part of the TSIG key. Both the DNS client and server must have this
//
//	secret to mutually authenticate DNS messages.
//
// Returns:
//
// If successful, returns a slice of DNS records related to the domain. If there are any errors during the
// process, the function returns an error.
func fetchZoneRecords(domain, dnsServer, keyName, secret string) ([]Record, error) {
	// Create a new DNS message.
	m := new(dns.Msg)

	// Create a transfer object.
	t := new(dns.Transfer)

	// Associate the keyName with the provided secret for TSIG authentication.
	t.TsigSecret = map[string]string{keyName: secret}

	// Set the request type to AXFR to fetch all records of the domain.
	m.SetAxfr(domain)

	// Set up TSIG (Transaction Signature) for authentication.
	m.SetTsig(keyName, dns.HmacSHA256, 300, time.Now().Unix())

	// Initiate the transfer.
	channels, err := t.In(m, dnsServer)
	if err != nil {
		return nil, err
	}

	var records []Record
	var rr []dns.RR
	// Process the responses to collect records.
	for env := range channels {
		if env.Error != nil {
			return nil, env.Error
		}
		rr = append(rr, env.RR...)
	}
	for _, r := range rr {
		switch record := r.(type) {
		case *dns.A:
			records = append(records, NewRecord("A", record.Hdr.Name, record.A.String(), uint(record.Hdr.Ttl)))
		case *dns.AAAA:
			records = append(records, NewRecord("AAAA", record.Hdr.Name, record.AAAA.String(), uint(record.Hdr.Ttl)))
		case *dns.NS:
			records = append(records, NewRecord("NS", record.Hdr.Name, record.Ns, uint(record.Hdr.Ttl)))
		}
	}

	return records, nil
}
