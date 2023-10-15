package dnsclient

import (
	"fmt"
	"slices"
	"sync"
)

type MockDNSClient struct {
	cache []Record
	mutex sync.RWMutex
}

func NewMockDNSClient() *MockDNSClient {
	return &MockDNSClient{
		cache: make([]Record, 0),
		mutex: sync.RWMutex{},
	}
}
func NewMockDNSClientWithTestRecords() *MockDNSClient {
	m := &MockDNSClient{
		cache: make([]Record, 0),
		mutex: sync.RWMutex{},
	}
	m.AddRecord(NewRecord("A", "foo.rusty-leipzig.com.", "192.168.1.1", 100))
	m.AddRecord(NewRecord("AAAA", "foo.rusty-leipzig.com.", "::1", 100))
	m.AddRecord(NewRecord("A", "bar.rusty-leipzig.com.", "192.168.1.1", 100))
	m.AddRecord(NewRecord("AAAA", "bar.rusty-leipzig.com.", "::1", 100))
	return m
}

func (m *MockDNSClient) GetRecords() []Record {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	recordsCopy := make([]Record, len(m.cache))
	copy(recordsCopy, m.cache)
	return recordsCopy
}

func (m *MockDNSClient) GetRecordForFQDN(targetFQDN, recordType string) *Record {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, record := range m.cache {
		if record.Type == recordType && record.FQDN == targetFQDN {
			recordCopy := record
			return &recordCopy
		}
	}
	return nil
}

func (m *MockDNSClient) GetRecordByFQDNAndType(recordFQDN, recordType string) *Record {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	idx := slices.IndexFunc(m.cache, func(record Record) bool {
		return record.Type == recordType && record.FQDN == recordFQDN
	})
	if idx != -1 {
		recordCopy := m.cache[idx]
		return &recordCopy
	}
	return nil
}

func (m *MockDNSClient) GetRecordByHash(targetHash string) *Record {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, record := range m.cache {
		if record.Hash == targetHash {
			recordCopy := record
			return &recordCopy
		}
	}
	return nil
}

func (m *MockDNSClient) AddRecord(record Record) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Here we just simulate adding by appending to our in-memory slice
	m.cache = append(m.cache, record)
	return nil
}

func (m *MockDNSClient) RemoveRecord(record Record) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for i, r := range m.cache {
		if r.FQDN == record.FQDN && r.Type == record.Type && r.IP == record.IP {
			m.cache = append(m.cache[:i], m.cache[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("record not found")
}

func (m *MockDNSClient) Close() {
	return
}
