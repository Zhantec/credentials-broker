package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Infisical struct {
	WorkspaceID string `yaml:"workspace_id"`
	Environment string `yaml:"environment"`
}

type Caller struct {
	Key     string   `yaml:"key"`
	Targets []string `yaml:"targets"`
}

type Target struct {
	Name            string `yaml:"name"`
	Mode            string `yaml:"mode"`
	Driver          string `yaml:"driver,omitempty"`
	BaseURL         string `yaml:"base_url,omitempty"`
	InjectHeader    string `yaml:"inject_header,omitempty"`
	InjectPrefix    string `yaml:"inject_prefix,omitempty"`
	InfisicalSecret string `yaml:"infisical_secret"`
}

type Config struct {
	Infisical Infisical `yaml:"infisical"`
	Callers   []Caller  `yaml:"callers"`
	Targets   []Target  `yaml:"targets"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	return &cfg, nil
}

func (c *Config) FindTarget(name string) (*Target, bool) {
	for i := range c.Targets {
		if c.Targets[i].Name == name {
			return &c.Targets[i], true
		}
	}
	return nil, false
}

func (c *Config) FindCaller(key string) (*Caller, bool) {
	for i := range c.Callers {
		if c.Callers[i].Key == key {
			return &c.Callers[i], true
		}
	}
	return nil, false
}

// SecretPathAndName splits the config's dot-path-style secret reference into
// the secretPath and secret name Infisical's API expects as separate fields.
func (t *Target) SecretPathAndName() (path, name string) {
	idx := strings.LastIndex(t.InfisicalSecret, "/")
	if idx < 0 {
		return "/", t.InfisicalSecret
	}
	path = t.InfisicalSecret[:idx]
	if path == "" {
		path = "/"
	}
	return path, t.InfisicalSecret[idx+1:]
}
