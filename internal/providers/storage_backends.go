package providers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// FilesystemStorage implements StorageBackend for filesystem storage
type FilesystemStorage struct {
	basePath string
	logger   *logrus.Logger
	mutex    sync.RWMutex
}

// DatabaseStorage implements StorageBackend for database storage
type DatabaseStorage struct {
	db     *gorm.DB
	table  string
	logger *logrus.Logger
}

// MemoryStorage implements StorageBackend for in-memory storage (testing only)
type MemoryStorage struct {
	data   map[string][]byte
	logger *logrus.Logger
	mutex  sync.RWMutex
}

// StorageRecord represents a record in database storage
type StorageRecord struct {
	Key  string `gorm:"primaryKey;column:key"`
	Data []byte `gorm:"column:data"`
}

// NewFilesystemStorage creates a new filesystem storage backend
func NewFilesystemStorage(config map[string]interface{}, logger *logrus.Logger) (*FilesystemStorage, error) {
	basePath, ok := config["base_path"].(string)
	if !ok {
		basePath = "/tmp/keygrid-hsm-storage"
	}

	// Create base directory if it doesn't exist
	if err := os.MkdirAll(basePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create base directory: %w", err)
	}

	return &FilesystemStorage{
		basePath: basePath,
		logger:   logger,
	}, nil
}

func (fs *FilesystemStorage) Store(ctx context.Context, key string, data []byte) error {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	filePath := fs.getFilePath(key)
	dirPath := filepath.Dir(filePath)

	// Create directory if it doesn't exist
	if err := os.MkdirAll(dirPath, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dirPath, err)
	}

	// Write file atomically using temporary file
	tempFile := filePath + ".tmp"
	if err := os.WriteFile(tempFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write temporary file: %w", err)
	}

	if err := os.Rename(tempFile, filePath); err != nil {
		os.Remove(tempFile) // Clean up temp file
		return fmt.Errorf("failed to rename temporary file: %w", err)
	}

	return nil
}

func (fs *FilesystemStorage) Retrieve(ctx context.Context, key string) ([]byte, error) {
	fs.mutex.RLock()
	defer fs.mutex.RUnlock()

	filePath := fs.getFilePath(key)
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("key not found: %s", key)
		}
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	return data, nil
}

func (fs *FilesystemStorage) Delete(ctx context.Context, key string) error {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()

	filePath := fs.getFilePath(key)
	if err := os.Remove(filePath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("key not found: %s", key)
		}
		return fmt.Errorf("failed to delete file: %w", err)
	}

	return nil
}

func (fs *FilesystemStorage) List(ctx context.Context, prefix string) ([]string, error) {
	fs.mutex.RLock()
	defer fs.mutex.RUnlock()

	var keys []string
	prefixPath := fs.getFilePath(prefix)

	err := filepath.Walk(fs.basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if strings.HasPrefix(path, prefixPath) {
			// Convert file path back to key
			relPath, err := filepath.Rel(fs.basePath, path)
			if err != nil {
				return err
			}
			key := filepath.ToSlash(relPath)
			keys = append(keys, key)
		}

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	return keys, nil
}

func (fs *FilesystemStorage) Exists(ctx context.Context, key string) (bool, error) {
	fs.mutex.RLock()
	defer fs.mutex.RUnlock()

	filePath := fs.getFilePath(key)
	_, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check file existence: %w", err)
	}

	return true, nil
}

func (fs *FilesystemStorage) Health(ctx context.Context) error {
	// Check if base directory is writable
	testFile := filepath.Join(fs.basePath, ".health_check")
	if err := os.WriteFile(testFile, []byte("test"), 0600); err != nil {
		return fmt.Errorf("filesystem not writable: %w", err)
	}

	// Clean up test file
	os.Remove(testFile)
	return nil
}

func (fs *FilesystemStorage) Close() error {
	// Nothing to close for filesystem storage
	return nil
}

func (fs *FilesystemStorage) getFilePath(key string) string {
	// Sanitize key to prevent directory traversal
	sanitizedKey := strings.ReplaceAll(key, "..", "_")
	return filepath.Join(fs.basePath, sanitizedKey)
}

// NewDatabaseStorage creates a new database storage backend
func NewDatabaseStorage(config map[string]interface{}, logger *logrus.Logger) (*DatabaseStorage, error) {
	dsn, ok := config["dsn"].(string)
	if !ok {
		return nil, fmt.Errorf("database dsn is required")
	}

	table, ok := config["table"].(string)
	if !ok {
		table = "hsm_storage"
	}

	// Configure GORM logger - use silent mode to avoid noise
	gormConfig := &gorm.Config{
		// Using default logger with silent mode
	}

	db, err := gorm.Open(postgres.Open(dsn), gormConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	storage := &DatabaseStorage{
		db:     db,
		table:  table,
		logger: logger,
	}

	// Create table if it doesn't exist
	if err := storage.createTable(); err != nil {
		return nil, fmt.Errorf("failed to create storage table: %w", err)
	}

	return storage, nil
}

func (ds *DatabaseStorage) createTable() error {
	// Create table with proper schema
	sql := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			key TEXT PRIMARY KEY,
			data BYTEA NOT NULL,
			created_at TIMESTAMP DEFAULT NOW(),
			updated_at TIMESTAMP DEFAULT NOW()
		);
		
		CREATE INDEX IF NOT EXISTS idx_%s_key_prefix ON %s (key text_pattern_ops);
	`, ds.table, ds.table, ds.table)

	return ds.db.Exec(sql).Error
}

func (ds *DatabaseStorage) Store(ctx context.Context, key string, data []byte) error {
	record := StorageRecord{
		Key:  key,
		Data: data,
	}

	result := ds.db.WithContext(ctx).Table(ds.table).Save(&record)
	if result.Error != nil {
		return fmt.Errorf("failed to store data: %w", result.Error)
	}

	return nil
}

func (ds *DatabaseStorage) Retrieve(ctx context.Context, key string) ([]byte, error) {
	var record StorageRecord

	result := ds.db.WithContext(ctx).Table(ds.table).Where("key = ?", key).First(&record)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("key not found: %s", key)
		}
		return nil, fmt.Errorf("failed to retrieve data: %w", result.Error)
	}

	return record.Data, nil
}

func (ds *DatabaseStorage) Delete(ctx context.Context, key string) error {
	result := ds.db.WithContext(ctx).Table(ds.table).Where("key = ?", key).Delete(&StorageRecord{})
	if result.Error != nil {
		return fmt.Errorf("failed to delete data: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("key not found: %s", key)
	}

	return nil
}

func (ds *DatabaseStorage) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string

	result := ds.db.WithContext(ctx).Table(ds.table).
		Where("key LIKE ?", prefix+"%").
		Pluck("key", &keys)

	if result.Error != nil {
		return nil, fmt.Errorf("failed to list keys: %w", result.Error)
	}

	return keys, nil
}

func (ds *DatabaseStorage) Exists(ctx context.Context, key string) (bool, error) {
	var count int64

	result := ds.db.WithContext(ctx).Table(ds.table).
		Where("key = ?", key).
		Count(&count)

	if result.Error != nil {
		return false, fmt.Errorf("failed to check key existence: %w", result.Error)
	}

	return count > 0, nil
}

func (ds *DatabaseStorage) Health(ctx context.Context) error {
	// Test database connection
	sqlDB, err := ds.db.DB()
	if err != nil {
		return fmt.Errorf("failed to get database connection: %w", err)
	}

	if err := sqlDB.PingContext(ctx); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}

	return nil
}

func (ds *DatabaseStorage) Close() error {
	sqlDB, err := ds.db.DB()
	if err != nil {
		return fmt.Errorf("failed to get database connection: %w", err)
	}

	return sqlDB.Close()
}

// NewMemoryStorage creates a new in-memory storage backend (for testing)
func NewMemoryStorage(config map[string]interface{}, logger *logrus.Logger) (*MemoryStorage, error) {
	return &MemoryStorage{
		data:   make(map[string][]byte),
		logger: logger,
	}, nil
}

func (ms *MemoryStorage) Store(ctx context.Context, key string, data []byte) error {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	// Make a copy of the data to avoid external modification
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)
	ms.data[key] = dataCopy

	return nil
}

func (ms *MemoryStorage) Retrieve(ctx context.Context, key string) ([]byte, error) {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()

	data, exists := ms.data[key]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", key)
	}

	// Make a copy of the data to avoid external modification
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	return dataCopy, nil
}

func (ms *MemoryStorage) Delete(ctx context.Context, key string) error {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	if _, exists := ms.data[key]; !exists {
		return fmt.Errorf("key not found: %s", key)
	}

	delete(ms.data, key)
	return nil
}

func (ms *MemoryStorage) List(ctx context.Context, prefix string) ([]string, error) {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()

	var keys []string
	for key := range ms.data {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}

	return keys, nil
}

func (ms *MemoryStorage) Exists(ctx context.Context, key string) (bool, error) {
	ms.mutex.RLock()
	defer ms.mutex.RUnlock()

	_, exists := ms.data[key]
	return exists, nil
}

func (ms *MemoryStorage) Health(ctx context.Context) error {
	// Memory storage is always healthy if it exists
	return nil
}

func (ms *MemoryStorage) Close() error {
	ms.mutex.Lock()
	defer ms.mutex.Unlock()

	// Clear the data
	ms.data = make(map[string][]byte)
	return nil
}
