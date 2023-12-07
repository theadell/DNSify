package dnsservice

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/miekg/dns"
	"github.com/theadell/dnsify/internal/backoff"
)

func (c *Client) GetRecords() []Record {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	// Filter out immutable records
	var recordsCopy []Record
	for _, record := range c.cache {
		if !c.isImmutable(record) {
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

func (c *Client) GetRecordForFQDN(targetFQDN, recordType string) *Record {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	for _, record := range c.cache {
		if record.Data.RecordType() == recordType && record.Name == targetFQDN {
			recordCopy := record
			return &recordCopy
		}
	}
	return nil
}

func (c *Client) AddRecord(record Record) error {
	slog.Debug("Attempting to add record", "record", record)

	if c.isImmutable(record) {
		slog.Warn("Attempted to modify an immutable record", "record", record.Name)
		return ErrImmutableRecord
	}

	retryConfig := backoff.DefaultRetryConfig
	retryConfig.MaxRetries = 2

	if c.exists(record) {
		slog.Debug("Record already exists, will attempt to override it by deleting it and then creating it again", "record", record)
		removeRecordOp := func() error {
			return c.RemoveRecord(record)
		}
		err := backoff.RetryWithBackoff(removeRecordOp, retryConfig)
		if err != nil {
			return ErrRecordDeletion
		}
	}

	msg := new(dns.Msg)
	msg.SetUpdate(c.zone)

	resourceRecord, err := dns.NewRR(record.String())
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
	if c.isImmutable(record) {
		slog.Warn("Attempted to delete an immutable record", "record", record.Name)
		return ErrImmutableRecord
	}

	resourceRecordStr := record.String()
	resourceRecord, err := dns.NewRR(resourceRecordStr)
	if err != nil {
		return fmt.Errorf("failed to create Resource Record: %w", err)
	}

	msg := new(dns.Msg)
	msg.SetUpdate(c.zone)
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
		if r.String() == record.String() {
			c.cache = append(c.cache[:i], c.cache[i+1:]...)
			break
		}
	}

	slog.Info("Record removed successfully", "record", record)
	return nil
}
func hashRecord(record Record) string {
	data := record.Data.RecordType() + record.Name + record.Data.String() + strconv.FormatUint(uint64(record.TTL), 10)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (c *Client) isImmutable(record Record) bool {
	tguard := NewRecordGuard(record.Data.RecordType(), record.Name)
	if _, ok := c.guards.Immutable[tguard]; ok {
		return ok
	}
	wildcardGuard := NewRecordGuard("*", record.Name)
	if _, ok := c.guards.Immutable[wildcardGuard]; ok {
		return true
	}
	return false
}

func (c *Client) isAdminEditable(record Record) bool {
	tguard := NewRecordGuard(record.Data.RecordType(), record.Name)
	if _, ok := c.guards.AdminOnly[tguard]; ok {
		return ok
	}
	wildcardGuard := NewRecordGuard("*", record.Name)
	if _, ok := c.guards.AdminOnly[wildcardGuard]; ok {
		return true
	}
	return false
}

func (c *Client) isRecordGuarded(record Record) bool {
	return c.isImmutable(record) || c.isAdminEditable(record)
}

func (c *Client) exists(record Record) bool {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	for _, cachedRecord := range c.cache {
		if cachedRecord.Data.RecordType() == record.Data.RecordType() && cachedRecord.Name == record.Name {
			return true
		}
	}
	return false
}
