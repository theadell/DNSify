package apikeymanager

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"time"
)

type fileAPIKeyManager struct {
	keys     map[string][]APIKey
	mutex    sync.RWMutex
	filePath string
}

func NewFileAPIKeyManager(filePath string) (APIKeyManager, error) {
	manager := &fileAPIKeyManager{
		keys:     make(map[string][]APIKey),
		filePath: filePath,
	}
	if err := manager.loadKeys(); err != nil {
		return nil, err
	}
	return manager, nil
}

func (m *fileAPIKeyManager) loadKeys() error {
	data, err := os.ReadFile(m.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File not found is not an error; it will be created on first save.
		}
		return err
	}
	if len(data) == 0 {
		m.keys = make(map[string][]APIKey)
		return nil
	}
	if err := json.Unmarshal(data, &m.keys); err != nil {
		return err
	}
	return nil
}

func (m *fileAPIKeyManager) saveKeys() error {

	data, err := json.Marshal(m.keys)
	if err != nil {
		return err
	}

	return os.WriteFile(m.filePath, data, 0644)
}

func (m *fileAPIKeyManager) CreateKey(ctx context.Context, userID, label string) (APIKey, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for _, k := range m.keys[userID] {
		if k.Label == label {
			return APIKey{}, nil // Key already exists
		}
	}
	key, err := generateSecureKey(32)
	if err != nil {
		return APIKey{}, err
	}
	newKey := APIKey{UserID: userID, Label: label, Key: key, CreatedAt: time.Now()}
	m.keys[userID] = append(m.keys[userID], newKey)

	if err := m.saveKeys(); err != nil {
		return APIKey{}, err
	}

	return newKey, nil
}

func (m *fileAPIKeyManager) GetKeys(ctx context.Context, userID string) ([]APIKey, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return append([]APIKey(nil), m.keys[userID]...), nil
}

func (m *fileAPIKeyManager) DeleteKey(ctx context.Context, userID, label string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	for i, key := range m.keys[userID] {
		if key.Label == label {
			m.keys[userID] = append(m.keys[userID][:i], m.keys[userID][i+1:]...)
			return m.saveKeys()
		}
	}

	return nil
}
