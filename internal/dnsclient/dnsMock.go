package dnsclient

import (
	"fmt"
	"log/slog"
	"sync"
)

type MockDNSClient struct {
	Records []Record
	mutex   sync.RWMutex
}

func NewMockDNSClient() *MockDNSClient {
	return &MockDNSClient{
		Records: make([]Record, 0),
		mutex:   sync.RWMutex{},
	}
}
func NewMockDNSClientWithTestRecords() *MockDNSClient {
	m := &MockDNSClient{
		Records: make([]Record, 0),
		mutex:   sync.RWMutex{},
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
	slog.Info("Get Records called", "len of records", len(m.Records), "records", m.Records)
	recordsCopy := make([]Record, len(m.Records))
	copy(recordsCopy, m.Records)
	return recordsCopy
}

func (m *MockDNSClient) GetRecordForFQDN(targetFQDN, recordType string) *Record {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, record := range m.Records {
		if record.Type == recordType && record.FQDN == targetFQDN {
			recordCopy := record
			return &recordCopy
		}
	}
	return nil
}
func (m *MockDNSClient) GetRecordByHash(targetHash string) *Record {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	for _, record := range m.Records {
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
	m.Records = append(m.Records, record)
	return nil
}

func (m *MockDNSClient) RemoveRecord(record Record) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for i, r := range m.Records {
		if r.FQDN == record.FQDN && r.Type == record.Type && r.IP == record.IP {
			m.Records = append(m.Records[:i], m.Records[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("record not found")
}

func (m *MockDNSClient) Close() {
	return
}
