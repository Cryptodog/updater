package main

import (
	"fmt"
	"regexp"
)

type Config struct {
	DeployDir                       string    `json:"deploy_dir"`
	Targets                         []*Target `json:"targets"`
	PublicSigningKeyFile            string    `json:"public_signing_key_file"`
	UnsafeSkipSignatureVerification bool      `json:"unsafe_skip_signature_verification"`
	UpdateInterval                  int       `json:"update_interval"`
}

type Target struct {
	Name  string
	Owner string
	Repo  string
}

func (c *Config) Validate() error {
	if c.DeployDir == "" {
		return fmt.Errorf("deploy directory must be set")
	}
	if c.UpdateInterval <= 0 {
		return fmt.Errorf("update interval must be >0")
	}
	if !c.UnsafeSkipSignatureVerification && c.PublicSigningKeyFile == "" {
		return fmt.Errorf("public signing key file must be set if signature verification is enabled")
	}
	if len(c.Targets) == 0 {
		return fmt.Errorf("at least one target must be set")
	}

	targetNames := make(map[string]bool)
	targetNameRegex := regexp.MustCompile(`^[\w-]+$`)
	for i, target := range c.Targets {
		if target.Name == "" {
			return fmt.Errorf("name for target %d must be set", i)
		}
		if !targetNameRegex.MatchString(target.Name) {
			return fmt.Errorf("name for target %d must match pattern %s", i, targetNameRegex.String())
		}
		if target.Owner == "" {
			return fmt.Errorf("owner for target %d must be set", i)
		}
		if target.Repo == "" {
			return fmt.Errorf("repo for target %d must be set", i)
		}
		if targetNames[target.Name] {
			return fmt.Errorf("target %d has duplicate name", i)
		}
		targetNames[target.Name] = true
	}
	return nil
}
