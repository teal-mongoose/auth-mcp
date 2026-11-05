// Command dev runs the whole local stack from one command: a Firebase emulator per project, the
// generic accounts, the mock providers and the server. Run it from the repo root, and stop it with
// Ctrl+C.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/teal-mongoose/auth-mcp/internal/adminscreen"
	"github.com/teal-mongoose/auth-mcp/internal/broker"
	"github.com/teal-mongoose/auth-mcp/internal/devenv"
	"github.com/teal-mongoose/auth-mcp/internal/fixtures"
	"github.com/teal-mongoose/auth-mcp/internal/mockidp"
	"github.com/teal-mongoose/auth-mcp/internal/safety"
	"github.com/teal-mongoose/auth-mcp/internal/seed"
	"github.com/teal-mongoose/auth-mcp/internal/server"
	"github.com/teal-mongoose/auth-mcp/internal/testapp"
)

const emulatorStartTimeout = 2 * time.Minute

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "dev:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if _, err := os.Stat("firebase.json"); err != nil {
		return errors.New("run this from the repo root")
	}
	if err := devenv.SetEmulatorEnv(); err != nil {
		return err
	}

	// Check before starting anything, and listen first, so a bad setup or a taken port fails fast.
	cfg := devenv.SafetyConfig()
	srv, err := server.New(devenv.BindAddr, func() error { return safety.Check(cfg) })
	if err != nil {
		return err
	}

	exited := make(chan error, len(devenv.Emulators()))
	for _, emulator := range devenv.Emulators() {
		cmd, err := startEmulator(emulator, exited)
		if err != nil {
			return err
		}
		defer stopProcessTree(cmd)
	}

	if err := waitForEmulators(ctx, exited); err != nil {
		return err
	}

	if err := fixtures.SetConnectionSecrets(); err != nil {
		return err
	}
	clients, err := devenv.AuthClients(ctx)
	if err != nil {
		return err
	}
	fs, err := devenv.FirestoreClient(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = fs.Close() }()
	if err := seed.Run(ctx, cfg, clients, broker.NewStore(fs)); err != nil {
		return err
	}

	providers := make([]*mockidp.Provider, 0, len(mockidp.Providers()))
	for _, config := range mockidp.Providers() {
		provider, err := mockidp.Start(config)
		if err != nil {
			return err
		}
		defer func() { _ = provider.Shutdown() }()
		providers = append(providers, provider)
	}

	testApps, err := startTestApps()
	if err != nil {
		return err
	}
	for _, testApp := range testApps {
		defer func() { _ = testApp.Close() }()
	}

	handler, closeHandler, err := devenv.NewHandler(ctx, devenv.BaseURL)
	if err != nil {
		return err
	}
	defer closeHandler()

	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- srv.Serve(serveCtx, handler) }()

	printSummary(srv.Addr(), providers)

	select {
	case <-ctx.Done():
		fmt.Println("dev: stopping")
	case err := <-exited:
		cancel()
		return errors.Join(fmt.Errorf("an emulator stopped: %w", err), <-served)
	case err := <-served:
		return err
	}
	return <-served
}

func startTestApps() ([]*http.Server, error) {
	hosts := map[string]string{}
	for _, project := range devenv.Projects() {
		hosts[project.ID] = project.AuthEmulatorHost
	}

	servers := make([]*http.Server, 0, len(fixtures.Apps()))
	for _, app := range fixtures.Apps() {
		redirectURI := app.RedirectURIs[0]
		addr := strings.TrimSuffix(strings.TrimPrefix(redirectURI, "http://"), "/")
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("test app %s: %w", app.ID, err)
		}
		config := testapp.Config{
			AppID:           app.ID,
			Name:            app.Name,
			ProjectID:       app.ProjectID,
			APIKey:          "fake-api-key",
			AuthEmulatorURL: "http://" + hosts[app.ProjectID],
			BrokerURL:       devenv.BaseURL,
			RedirectURI:     redirectURI,
		}
		handler := testapp.Handler(config)
		if app.ID == fixtures.AppAdmin {
			handler = adminscreen.Handler(adminscreen.Config{
				AppID:           app.ID,
				Name:            app.Name,
				ProjectID:       app.ProjectID,
				APIKey:          "fake-api-key",
				AuthEmulatorURL: "http://" + hosts[app.ProjectID],
				BrokerURL:       devenv.BaseURL,
				RedirectURI:     redirectURI,
			})
		}
		testServer := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
		go func() { _ = testServer.Serve(listener) }()
		servers = append(servers, testServer)
	}
	return servers, nil
}

func startEmulator(emulator devenv.Emulator, exited chan<- error) (*exec.Cmd, error) {
	cmd := exec.Command("firebase", "emulators:start",
		"--project", emulator.Project,
		"--config", emulator.Config,
		"--only", emulator.Only)
	cmd.Env = withoutEmulatorVars(os.Environ())
	label := emulator.Project + ": "
	cmd.Stdout = &prefixWriter{prefix: label, out: os.Stdout}
	cmd.Stderr = &prefixWriter{prefix: label, out: os.Stderr}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting the %s emulator: %w", emulator.Project, err)
	}
	go func() {
		err := cmd.Wait()
		exited <- fmt.Errorf("%s: %v", emulator.Project, err)
	}()
	return cmd, nil
}

// withoutEmulatorVars keeps this process's emulator addresses from leaking into the Firebase CLI,
// which manages its own.
func withoutEmulatorVars(env []string) []string {
	kept := make([]string, 0, len(env))
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		if strings.EqualFold(name, "FIREBASE_AUTH_EMULATOR_HOST") || strings.EqualFold(name, "FIRESTORE_EMULATOR_HOST") {
			continue
		}
		kept = append(kept, entry)
	}
	return kept
}

func waitForEmulators(ctx context.Context, exited <-chan error) error {
	ctx, cancel := context.WithTimeout(ctx, emulatorStartTimeout)
	defer cancel()

	var hosts []string
	for _, emulator := range devenv.Emulators() {
		hosts = append(hosts, emulator.Hosts...)
	}

	for _, host := range hosts {
		for !listening(host) {
			select {
			case err := <-exited:
				return fmt.Errorf("an emulator stopped during startup: %w", err)
			case <-ctx.Done():
				return fmt.Errorf("waiting for an emulator on %s: %w", host, ctx.Err())
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	return nil
}

func listening(host string) bool {
	conn, err := net.DialTimeout("tcp", host, 250*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// stopProcessTree stops the Firebase CLI and the emulators it started.
func stopProcessTree(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	if runtime.GOOS == "windows" {
		_ = exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid)).Run()
		return
	}
	_ = cmd.Process.Signal(os.Interrupt)
}

func printSummary(addr string, providers []*mockidp.Provider) {
	fmt.Println()
	fmt.Println("auth-mcp dev stack is running. Everything is local, with generic accounts only.")
	fmt.Println("  Server:      http://" + addr)
	fmt.Println("  Emulator UI: http://127.0.0.1:4002 (broker project)")
	for _, project := range devenv.Projects() {
		fmt.Printf("  Auth emulator, %s: http://%s\n", project.ID, project.AuthEmulatorHost)
	}
	for i, config := range mockidp.Providers() {
		fmt.Printf("  Mock provider, %s: %s\n", config.Name, providers[i].Issuer())
	}
	for _, app := range fixtures.Apps() {
		fmt.Printf("  %s: %s\n", app.Name, app.RedirectURIs[0])
	}
	fmt.Println("Stop with Ctrl+C.")
	fmt.Println()
}

// prefixWriter labels each line of a child process's output.
type prefixWriter struct {
	prefix  string
	out     io.Writer
	partial []byte
}

func (w *prefixWriter) Write(data []byte) (int, error) {
	w.partial = append(w.partial, data...)
	for {
		line, rest, found := strings.Cut(string(w.partial), "\n")
		if !found {
			return len(data), nil
		}
		if _, err := fmt.Fprintln(w.out, w.prefix+strings.TrimRight(line, "\r")); err != nil {
			return 0, err
		}
		w.partial = []byte(rest)
	}
}
