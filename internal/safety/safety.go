// Package safety keeps emulator mode away from anything real.
//
// The Firebase Admin SDK skips ID token signature checks whenever
// FIREBASE_AUTH_EMULATOR_HOST is set, so anyone able to reach a server in this mode could forge an
// admin token. Check refuses to let the server start unless it is reachable only from this machine
// and can only touch emulators.
package safety

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
)

// Project is a Firebase project and the Auth emulator that serves it. Each project has its own
// emulator because one emulator sends every browser sign-in to its default project.
type Project struct {
	ID               string
	AuthEmulatorHost string
}

// Config is what the startup check looks at.
type Config struct {
	AuthEmulatorHost      string
	FirestoreEmulatorHost string
	BindAddr              string
	CredentialsFile       string
	Projects              []Project
}

// FromEnv builds a Config from the environment, for a server binding to bindAddr and using
// projects.
func FromEnv(bindAddr string, projects []Project) Config {
	return Config{
		AuthEmulatorHost:      os.Getenv("FIREBASE_AUTH_EMULATOR_HOST"),
		FirestoreEmulatorHost: os.Getenv("FIRESTORE_EMULATOR_HOST"),
		BindAddr:              bindAddr,
		CredentialsFile:       os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"),
		Projects:              projects,
	}
}

// Check returns every reason the server must not start, or nil if there are none.
func Check(c Config) error {
	var errs []error

	if err := checkEmulatorHost("FIREBASE_AUTH_EMULATOR_HOST", c.AuthEmulatorHost); err != nil {
		errs = append(errs, err)
	}
	if err := checkEmulatorHost("FIRESTORE_EMULATOR_HOST", c.FirestoreEmulatorHost); err != nil {
		errs = append(errs, err)
	}

	if host, _, err := net.SplitHostPort(c.BindAddr); err != nil {
		errs = append(errs, fmt.Errorf("bind address %q is not host:port", c.BindAddr))
	} else if host != "127.0.0.1" {
		errs = append(errs, fmt.Errorf("bind address %q must use 127.0.0.1", c.BindAddr))
	}

	if c.CredentialsFile != "" {
		errs = append(errs, errors.New("GOOGLE_APPLICATION_CREDENTIALS must not be set: this server takes no service account key"))
	}

	if len(c.Projects) == 0 {
		errs = append(errs, errors.New("no projects given"))
	}
	for _, p := range c.Projects {
		if !strings.HasPrefix(p.ID, "demo-") {
			errs = append(errs, fmt.Errorf("project id %q must start with demo-", p.ID))
		}
		if err := checkEmulatorHost("Auth emulator for "+p.ID, p.AuthEmulatorHost); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// checkEmulatorHost requires a host:port on this machine. An exact match on the host means a name
// such as localhost.example.com fails.
func checkEmulatorHost(name, value string) error {
	if value == "" {
		return fmt.Errorf("%s must be set", name)
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil || port == "" {
		return fmt.Errorf("%s=%q is not host:port", name, value)
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("%s=%q must point at this machine", name, value)
}
