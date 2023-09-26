package main

import (
	"sync"

	"github.com/theadell/dns-api/internal/dnsutils"
)

type RecordCache struct {
	mu      *sync.RWMutex
	records []dnsutils.Record
}

func (recordCache *RecordCache) get() []dnsutils.Record {
	recordCache.mu.RLock()
	defer recordCache.mu.RUnlock()
	return recordCache.records
}

func (recordCache *RecordCache) set(rs []dnsutils.Record) {
	recordCache.mu.Lock()
	recordCache.records = rs
	recordCache.mu.Unlock()
}
func (recordCache *RecordCache) refresh(zoneFilePath string) error {
	records, err := dnsutils.ReadRecords(zoneFilePath)
	if err != nil {
		return err
	}
	recordCache.set(records)
	return nil
}
