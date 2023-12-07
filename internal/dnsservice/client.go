package dnsservice

import (
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/theadell/dnsify/internal/backoff"
)

var ErrServerNotReachable = errors.New("server not reachable")

type Service interface {
	HealthCheck() HealthState
	GetRecords() []Record
	AddRecord(Record) error
	RemoveRecord(Record) error
	GetRecordByHash(string) *Record
	GetRecordForFQDN(string, string) *Record
	GetZone() string
	GetIPv4() string
	GetIPv6() string
	Close()
}

type Client struct {
	cache               []Record
	guards              GuardMap
	mutex               sync.RWMutex
	client              *dns.Client
	zone                string
	ipv4                string
	ipv6                string
	serverAddr          string
	tsigKey             string
	SyncInterval        int
	HealthCheckInterval int
	done                chan bool
	healthState         HealthState
	wg                  sync.WaitGroup
}
type HealthState struct {
	ServerReachable bool
	LastChecked     time.Time
	LastSynced      time.Time
	SyncError       error
	CheckError      error
}

func NewClient(config DNSConfig) (*Client, error) {
	if err := validateConfig(&config); err != nil {
		return nil, err
	}
	client := &Client{
		cache:      make([]Record, 0),
		mutex:      sync.RWMutex{},
		guards:     parseGuards(config.Guards, config.Zone),
		client:     new(dns.Client),
		zone:       config.Zone,
		ipv4:       config.Ipv4,
		ipv6:       config.Ipv6,
		serverAddr: config.Addr,
		tsigKey:    config.TsigKey,
		done:       make(chan bool),
		healthState: HealthState{
			ServerReachable: true,
			LastChecked:     time.Now(),
			LastSynced:      time.Now(),
		},
	}
	client.client.TsigSecret = map[string]string{config.TsigKey: config.TsigSecret}
	if err := client.fetchAndCacheRecords(); err != nil {
		return nil, err
	}

	client.wg.Add(2)
	go client.periodicHealthCheck(time.Duration(config.HealthCheckInterval) * time.Second)
	go client.periodicSyncRecords(time.Duration(config.SyncInterval) * time.Second)
	return client, nil
}

func (c *Client) GetZone() string {
	return c.zone
}

func (c *Client) GetIPv4() string {
	return c.ipv4
}

func (c *Client) GetIPv6() string {
	return c.ipv6
}

func (c *Client) HealthCheck() HealthState {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.healthState
}

func (c *Client) Close() {
	close(c.done)
	c.wg.Wait()
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

		var recordData RecordData
		recordName := r.Header().Name
		recordTTL := uint(r.Header().Ttl)

		switch record := r.(type) {
		case *dns.A:
			recordData = &ARecord{IP: record.A.String()}
		case *dns.AAAA:
			recordData = &AAAARecord{IPv6: record.AAAA.String()}
		case *dns.NS:
			recordData = &NSRecord{NameServer: record.Ns}
		case *dns.CNAME:
			recordData = &CNAMERecord{Alias: record.Target}
		case *dns.MX:
			recordData = &MXRecord{Priority: uint16(record.Preference), MailServer: record.Mx}
		case *dns.TXT:
			recordData = &TXTRecord{Text: strings.Join(record.Txt, "")}
		default:
			continue // Skip unsupported record types
		}

		records = append(records, NewRecord(recordName, recordTTL, recordData))
	}

	return records, nil
}

func (c *Client) fetchAndCacheRecords() error {
	return backoff.RetryWithBackoff(func() error {
		records, err := fetchZoneRecords(c.zone, c.serverAddr, c.tsigKey, c.client.TsigSecret[c.tsigKey])
		c.mutex.Lock()
		defer c.mutex.Unlock()
		if err != nil {
			c.healthState.SyncError = err
			slog.Error("Failed to fetch records. Retrying...", "error", err.Error())
			return err
		}
		c.cache = records
		return nil
	}, backoff.DefaultRetryConfig)
}

func (c *Client) periodicSyncRecords(interval time.Duration) {
	defer c.wg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			err := c.fetchAndCacheRecords()
			c.mutex.Lock()
			if err != nil {
				c.healthState.SyncError = err
				slog.Error("Failed to synchronize records", "error", err.Error())
			} else {
				c.healthState.LastSynced = time.Now()
				c.healthState.SyncError = nil
				slog.Info("Records synchronized successfully")
			}
			c.mutex.Unlock()

		case <-c.done:
			slog.Info("Terminating periodic record synchronization")
			return
		}
	}
}

func (c *Client) periodicHealthCheck(interval time.Duration) {
	defer c.wg.Done()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			reachable := c.isServerReachable()
			c.mutex.Lock()
			c.healthState.ServerReachable = reachable
			c.healthState.LastChecked = time.Now()
			if !reachable {
				c.healthState.CheckError = ErrServerNotReachable
				slog.Error("DNS server not reachable")
			} else {
				c.healthState.CheckError = nil
			}
			c.mutex.Unlock()

		case <-c.done:
			slog.Info("Terminating periodic health check")
			return
		}
	}
}

func (c *Client) isServerReachable() bool {
	m := new(dns.Msg)
	m.SetQuestion(c.zone, dns.TypeSOA)
	r, _, err := c.client.Exchange(m, c.serverAddr)
	return err == nil && len(r.Answer) > 0
}
