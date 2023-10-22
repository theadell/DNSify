package dnsservice

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
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
	GetRecordByFQDNAndType(string, string) *Record
	Close()
}

type RecordGuards struct {
	Immutable     []string `mapstructure:"immutable"`
	AdminEditable []string `mapstructure:"admin_only"`
}

type DNSClientConfig struct {
	TSIGKey      string       `mapstructure:"tsigKey"`
	TSIGSecret   string       `mapstructure:"tsigSecret"`
	Host         string       `mapstructure:"host"`
	Port         uint16       `mapstructure:"port"`
	Zone         string       `mapstructure:"zone"`
	SyncInterval int          `mapstructure:"SyncInterval"`
	Guards       RecordGuards `mapstructure:"guards"`
}

type Client struct {
	cache        []Record
	guards       RecordGuards
	mutex        sync.RWMutex
	client       *dns.Client
	zone         string
	host         net.IP
	port         uint16
	serverAddr   string
	tsigKey      string
	SyncInterval int
	done         chan bool
	healthState  HealthState
	wg           sync.WaitGroup
}
type HealthState struct {
	ServerReachable bool
	LastChecked     time.Time
	LastSynced      time.Time
	SyncError       error
	CheckError      error
}

func NewClient(config DNSClientConfig) (*Client, error) {
	if err := validateConfig(&config); err != nil {
		return nil, err
	}
	client := &Client{
		cache:        make([]Record, 0),
		guards:       config.Guards,
		mutex:        sync.RWMutex{},
		client:       new(dns.Client),
		zone:         config.Zone,
		host:         net.IP(config.Host),
		port:         config.Port,
		serverAddr:   fmt.Sprintf("%s:%d", config.Host, config.Port),
		tsigKey:      config.TSIGKey,
		SyncInterval: config.SyncInterval,
		done:         make(chan bool),
	}

	client.client.TsigSecret = map[string]string{config.TSIGKey: config.TSIGSecret}
	if err := client.fetchAndCacheRecords(); err != nil {
		return nil, err
	}

	client.wg.Add(2)
	go client.periodicHealthCheck(1 * time.Minute)
	go client.periodicSyncRecords(time.Duration(client.SyncInterval) * time.Minute)
	return client, nil
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
