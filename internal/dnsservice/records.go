package dnsservice

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/miekg/dns"
)

var (
	ErrImmutableRecord = errors.New("attempted to modify an immutable record")
	ErrNotAuthorized   = errors.New("not authorized to perform this action")
	ErrRecordCreation  = errors.New("failed to create record")
	ErrRecordDeletion  = errors.New("failed to delete record")
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

func (c *Client) GetRecords() []Record {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	// Filter out immutable records
	var recordsCopy []Record
	for _, record := range c.cache {
		if !c.isImmutable(record.Type, record.FQDN) {
			recordsCopy = append(recordsCopy, record)
		}
	}

	return recordsCopy
}

func (c *Client) GetRecordByHash(targetHash string) *Record {
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
func (c *Client) GetRecordByFQDNAndType(recordFQDN, recordType string) *Record {
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

func (c *Client) GetRecordForFQDN(targetFQDN, recordType string) *Record {
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

func (c *Client) AddRecord(record Record) error {
	slog.Debug("Attempting to add record", "record", record)

	if c.isImmutable(record.Type, record.FQDN) {
		slog.Warn("Attempted to modify an immutable record", "record", record.FQDN)
		return ErrImmutableRecord
	}

	msg := new(dns.Msg)
	msg.SetUpdate(c.zone)

	resourceRecord, err := dns.NewRR(fmt.Sprintf("%s %s %s", record.FQDN, record.Type, record.IP))
	if err != nil {
		slog.Error("Failed to create new resource record", "error", err)
		return fmt.Errorf("%w: %v", ErrRecordCreation, err)
	}

	msg.Insert([]dns.RR{resourceRecord})
	msg.SetTsig(c.tsigKey, dns.HmacSHA256, 300, time.Now().Unix())

	replyMsg, _, err := c.client.Exchange(msg, c.serverAddr)
	if err != nil {
		slog.Error("Failed to exchange DNS message", "error", err)
		return fmt.Errorf("failed to create new resource record: %w", err)
	}

	if replyMsg.Rcode != dns.RcodeSuccess {
		slog.Error("Failed to update record", "status_code", replyMsg.Rcode)
		return fmt.Errorf("%w: status code %d", ErrRecordCreation, replyMsg.Rcode)
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()
	record.Hash = hashRecord(record)
	c.cache = append(c.cache, record)

	slog.Info("Record added successfully", "record", record)
	return nil
}

func (c *Client) RemoveRecord(record Record) error {
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
		return fmt.Errorf("%w: status code %d", ErrRecordDeletion, replyMsg.Rcode)
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
