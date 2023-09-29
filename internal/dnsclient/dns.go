package dnsclient

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Record struct {
	Type string
	FQDN string
	IP   string
	TTL  uint
}

type DNSClient interface {
	GetRecords() []Record
	AddRecord(record Record) error
	RemoveRecord(record Record) error
}

type DNSClientConfig struct {
	ZoneFilePath string `mapstructure:"zoneFilePath"`
	TSIGKey      string `mapstructure:"tsigKey"`
	TSIGSecret   string `mapstructure:"tsigSecret"`
	Host         string `mapstructure:"host"`
	Port         uint16 `mapstructure:"port"`
	Zone         string `mapstructure:"zone"`
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
		done:         make(chan bool),
	}

	client.client.TsigSecret = map[string]string{config.TSIGKey: config.TSIGSecret}

	err := client.populateCache()
	if err != nil {
		return nil, err
	}
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
	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			err := c.populateCache()
			if err != nil {
				slog.Error("Failed to synchronize records", err)
			} else {
				slog.Info("Records synchronized successfully")
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
