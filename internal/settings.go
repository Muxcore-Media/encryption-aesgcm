package internal

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Muxcore-Media/core/pkg/contracts"
	encryptionv1 "github.com/Muxcore-Media/core/proto/gen/muxcore/encryption/v1"
)

func (m *Module) Settings() []contracts.SettingDef {
	return m.settingsDefs()
}

func (m *Module) UpdateSetting(key, value string) error {
	return m.updateSetting(key, value)
}

func (m *Module) settingsDefs() []contracts.SettingDef {
	m.cfgMu.RLock()
	keyFile := m.keyFile
	m.cfgMu.RUnlock()

	m.mu.RLock()
	active := m.active
	keyCount := len(m.keys)
	m.mu.RUnlock()

	return []contracts.SettingDef{
		{
			Key:         "key_file",
			Label:       "Keyring / Master Key File",
			Type:        contracts.SettingTypeString,
			Value:       keyFile,
			Default:     "/var/lib/encryption-aesgcm/master.key",
			Description: "Path to an existing JSON keyring or legacy hex key file (ENCRYPTION_KEY_FILE); must already exist — updates reload the ring live",
			Group:       "Keys",
		},
		{
			Key:         "active_key_id",
			Label:       "Active Key ID",
			Type:        contracts.SettingTypeInt,
			Value:       strconv.FormatUint(uint64(active), 10),
			Description: "Read-only id of the key used for new Encrypt operations",
			Group:       "Keys",
		},
		{
			Key:         "key_count",
			Label:       "Key Count",
			Type:        contracts.SettingTypeInt,
			Value:       strconv.Itoa(keyCount),
			Description: "Read-only number of keys retained in the ring (historical keys remain for Decrypt)",
			Group:       "Keys",
		},
		{
			Key:         "rotate_key",
			Label:       "Rotate Key",
			Type:        contracts.SettingTypeString,
			Value:       "",
			Description: "Set to any non-empty value to generate a new active key and persist the keyring",
			Group:       "Keys",
		},
	}
}

func (m *Module) updateSetting(key, value string) error {
	value = strings.TrimSpace(value)
	switch key {
	case "key_file", "ENCRYPTION_KEY_FILE":
		if value == "" {
			return fmt.Errorf("key_file must not be empty")
		}
		return m.setKeyFile(value)
	case "rotate_key":
		if value == "" {
			return fmt.Errorf("rotate_key requires a non-empty trigger value")
		}
		_, err := m.RotateKey(context.Background(), &encryptionv1.RotateKeyRequest{})
		return err
	case "active_key_id", "key_count":
		return fmt.Errorf("setting %q is read-only", key)
	default:
		return fmt.Errorf("unknown setting %q", key)
	}
}

func (m *Module) setKeyFile(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("key file %q does not exist", path)
		}
		return fmt.Errorf("key file %q: %w", path, err)
	}

	m.cfgMu.Lock()
	if path == m.keyFile {
		m.cfgMu.Unlock()
		return nil
	}
	old := m.keyFile
	m.keyFile = path
	m.cfgMu.Unlock()

	if err := m.loadExistingRing(); err != nil {
		m.cfgMu.Lock()
		m.keyFile = old
		m.cfgMu.Unlock()
		return fmt.Errorf("reload keyring: %w", err)
	}
	return nil
}
