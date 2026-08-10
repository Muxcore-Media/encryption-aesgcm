package internal

import (
	"fmt"
	"strings"

	"github.com/Muxcore-Media/core/pkg/contracts"
)

func (m *Module) Settings() []contracts.SettingDef {
	return m.settingsDefs()
}

func (m *Module) UpdateSetting(key, value string) error {
	return m.updateSetting(key, value)
}

func (m *Module) settingsDefs() []contracts.SettingDef {
	m.cfgMu.RLock()
	defer m.cfgMu.RUnlock()
	return []contracts.SettingDef{
		{
			Key:         "key_file",
			Label:       "Keyring / Master Key File",
			Type:        contracts.SettingTypeString,
			Value:       m.keyFile,
			Default:     "/var/lib/encryption-aesgcm/master.key",
			Description: "Path to JSON keyring or legacy hex key file (ENCRYPTION_KEY_FILE); updates reload the ring live",
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
	default:
		return fmt.Errorf("unknown setting %q", key)
	}
}

func (m *Module) setKeyFile(path string) error {
	m.cfgMu.Lock()
	if path == m.keyFile {
		m.cfgMu.Unlock()
		return nil
	}
	old := m.keyFile
	m.keyFile = path
	m.cfgMu.Unlock()

	if err := m.loadOrBootstrapRing(); err != nil {
		m.cfgMu.Lock()
		m.keyFile = old
		m.cfgMu.Unlock()
		return fmt.Errorf("reload keyring: %w", err)
	}
	return nil
}
