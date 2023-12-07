package dnsservice

import (
	"fmt"
	"sync"
	"time"
)

type MockClient struct {
	cache []Record
	mutex sync.RWMutex
}

func NewMockClient() *MockClient {
	return &MockClient{
		cache: make([]Record, 0),
		mutex: sync.RWMutex{},
	}
}

func NewMockClientWithTestRecords() *MockClient {
	m := &MockClient{
		cache: make([]Record, 0),
		mutex: sync.RWMutex{},
	}
	m.AddRecord(NewRecord("foo.rusty-leipzig.com.", 100, &ARecord{IP: "192.168.1.1"}))
	m.AddRecord(NewRecord("foo.rusty-leipzig.com.", 100, &AAAARecord{IPv6: "::1"}))
	m.AddRecord(NewRecord("bar.rusty-leipzig.com.", 100, &ARecord{IP: "192.168.1.1"}))
	m.AddRecord(NewRecord("bar.rusty-leipzig.com.", 100, &AAAARecord{IPv6: "::1"}))
	return m
}

func (m *MockClient) GetZone() string {
	return "mock.example.com."
}

func (m *MockClient) GetIPv4() string {
	return "172.0.0.1"
}
func (m *MockClient) GetIPv6() string {
	return "::1"
}

func (m *MockClient) GetRecords() []Record {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	recordsCopy := make([]Record, len(m.cache))
	copy(recordsCopy, m.cache)
	return recordsCopy
}
func (m *MockClient) GetRecordForFQDN(targetFQDN, recordType string) *Record {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, record := range m.cache {
		if record.Data.RecordType() == recordType && record.Name == targetFQDN {
			recordCopy := record
			return &recordCopy
		}
	}
	return nil
}
func (m *MockClient) GetRecordByHash(targetHash string) *Record {
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

func (m *MockClient) AddRecord(record Record) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Here we just simulate adding by appending to our in-memory slice
	m.cache = append(m.cache, record)
	return nil
}

func (m *MockClient) RemoveRecord(record Record) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for i, r := range m.cache {
		if r.Name == record.Name && r.Data.RecordType() == record.Data.RecordType() && r.Data.String() == record.Data.String() {
			m.cache = append(m.cache[:i], m.cache[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("record not found")
}

func (m *MockClient) Close() {
	return
}

func (m *MockClient) HealthCheck() HealthState {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return HealthState{
		ServerReachable: true,
		LastChecked:     time.Now(),
		LastSynced:      time.Now(),
		SyncError:       nil,
		CheckError:      nil,
	}
}
