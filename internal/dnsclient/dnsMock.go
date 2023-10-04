package dnsclient

import (
	"fmt"
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
	return &MockDNSClient{
		Records: []Record{
			{Type: "A", FQDN: "test1.rusty-leipzig.com.", IP: "127.0.0.1"},
			{Type: "A", FQDN: "test2.rusty-leipzig.com.", IP: "127.0.0.2"},
			{Type: "AAAA", FQDN: "test3.rusty-leipzig.com.", IP: "2001:db8::ff00:42:8329"},
		},
		mutex: sync.RWMutex{},
	}
}

func (m *MockDNSClient) GetRecords() []Record {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	recordsCopy := make([]Record, len(m.Records))
	copy(recordsCopy, m.Records)
	return recordsCopy
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
