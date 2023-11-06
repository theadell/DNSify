package apikeymanager

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"sync"
	"testing"
)

func TestGetKeys(t *testing.T) {
	manager := &fileAPIKeyManager{

		keys: map[string][]APIKey{
			"user1": {
				{UserID: "user1", Label: "label1", Key: "key1"},
				{UserID: "user1", Label: "label2", Key: "key2"},
			},
			"user2": {
				{UserID: "user2", Label: "label1", Key: "key3"},
			},
		},
	}

	tests := []struct {
		name     string
		userID   string
		expected []APIKey
	}{
		{
			name:   "GetKeys for user1",
			userID: "user1",
			expected: []APIKey{
				{UserID: "user1", Label: "label1", Key: "key1"},
				{UserID: "user1", Label: "label2", Key: "key2"},
			},
		},
		{
			name:     "GetKeys for user2",
			userID:   "user2",
			expected: []APIKey{{UserID: "user2", Label: "label1", Key: "key3"}},
		},
		{
			name:     "GetKeys for non-existing user",
			userID:   "user3",
			expected: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			keys, err := manager.GetKeys(ctx, tc.userID)
			if err != nil {
				t.Errorf("GetKeys(%q) resulted in an error: %v", tc.userID, err)
			}
			if !reflect.DeepEqual(keys, tc.expected) {
				t.Errorf("GetKeys(%q) = %v, want %v", tc.userID, keys, tc.expected)
			}
		})
	}

}

func TestAPIKeyManagerConcurrency(t *testing.T) {
	// Create a temporary file
	tmpFile, err := os.CreateTemp("", "apikeymanager-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Initialize the APIKeyManager
	manager, err := NewFileAPIKeyManager(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to create APIKeyManager: %v", err)
	}

	numGoroutines := 10
	numOperations := 100

	var wg sync.WaitGroup

	// Phase 1: Concurrent key creation
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(i int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				_, err := manager.CreateKey(context.Background(), fmt.Sprintf("user%d", i), fmt.Sprintf("label%d", j))
				if err != nil {
					t.Errorf("Failed to create key: %v", err)
				}
			}
		}(i)
	}
	wg.Wait()

	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(i int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				err := manager.DeleteKey(context.Background(), fmt.Sprintf("user%d", i), fmt.Sprintf("label%d", j))
				if err != nil {
					t.Errorf("Failed to delete key: %v", err)
				}
			}
		}(i)
	}
	wg.Wait()

	for i := 0; i < numGoroutines; i++ {
		keys, err := manager.GetKeys(context.Background(), fmt.Sprintf("user%d", i))
		if err != nil {
			t.Errorf("Failed to get keys after deletion: %v", err)
		}
		if len(keys) != 0 {
			t.Errorf("Keys not deleted for user%d: got %d keys remaining", i, len(keys))
		}
	}
}

func TestAPIKeyManagerMixedReadWrite(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "apikeymanager-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	manager, err := NewFileAPIKeyManager(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to create APIKeyManager: %v", err)
	}

	// Prepop with some initial keys
	for i := 0; i < 5; i++ {
		for j := 0; j < 5; j++ {
			_, err := manager.CreateKey(context.Background(), fmt.Sprintf("user%d", i), fmt.Sprintf("label%d", j))
			if err != nil {
				t.Fatalf("Failed to prepopulate key: %v", err)
			}
		}
	}

	numGoroutines := 10
	numOperations := 100
	var wg sync.WaitGroup

	// Concurrent operations: create, get, and delete
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			for j := 0; j < numOperations; j++ {
				var err error
				switch j % 3 {
				case 0:
					_, err = manager.CreateKey(context.Background(), fmt.Sprintf("user%d", i), fmt.Sprintf("labelC%d", j))
				case 1:
					_, err = manager.GetKeys(context.Background(), fmt.Sprintf("user%d", i))
				case 2:
					err = manager.DeleteKey(context.Background(), fmt.Sprintf("user%d", i), fmt.Sprintf("label%d", j))
				}
				if err != nil {
					t.Errorf("Error in concurrent operation: %v", err)
				}
			}
		}(i)
	}

	wg.Wait()

}
