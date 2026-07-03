// BIND9 hardened init -- replaces entrypoint.sh + healthcheck.
// Static binary, zero shell dependency. CGO_ENABLED=0.
//
// Usage:
//
//	init --healthcheck      run Docker healthcheck (exit 0/1)
//	init --setup-dirs       create runtime directories (build-time, FROM scratch)
//	init [CMD [ARGS...]]    entrypoint: config check, then exec CMD
package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

const (
	namedUID    = 5300
	namedGID    = 5300
	defaultConf = "/etc/bind/named.conf"
	dnsAddr     = "127.0.0.1:53"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--healthcheck":
			os.Exit(healthcheck())
		case "--setup-dirs":
			if err := setupDirs(); err != nil {
				fmt.Fprintf(os.Stderr, "[init][ERROR] setup-dirs: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}
	if err := entrypoint(); err != nil {
		fmt.Fprintf(os.Stderr, "[init][ERROR] %v\n", err)
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// Setup directories -- called at build time in FROM scratch stage via
// RUN ["/usr/local/bin/init", "--setup-dirs"]
// Creates runtime dirs with correct ownership; no shell needed.
// ---------------------------------------------------------------------------

func setupDirs() error {
	type dir struct {
		path string
		mode os.FileMode
		uid  int
		gid  int
	}
	dirs := []dir{
		// Parent dirs -- 0755 root:root so non-root user can traverse
		{"/var", 0755, 0, 0},
		{"/var/cache", 0755, 0, 0},
		{"/var/run", 0755, 0, 0},
		{"/var/log", 0755, 0, 0},
		{"/run", 0755, 0, 0},
		// Leaf dirs owned by named (UID 5300)
		{"/var/cache/bind", 0755, namedUID, namedGID},
		{"/var/run/named", 0755, namedUID, namedGID},
		{"/run/named", 0755, namedUID, namedGID},
		{"/var/log/named", 0755, namedUID, namedGID},
		// Temp directory
		{"/tmp", 01777, 0, 0},
	}
	for _, d := range dirs {
		logf("mkdir %s (mode=%04o uid=%d gid=%d)", d.path, d.mode, d.uid, d.gid)
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return fmt.Errorf("mkdir %s: %w", d.path, err)
		}
		// MkdirAll applies umask; Chmod overrides to exact mode
		if err := os.Chmod(d.path, d.mode); err != nil {
			return fmt.Errorf("chmod %s: %w", d.path, err)
		}
		if err := os.Chown(d.path, d.uid, d.gid); err != nil {
			return fmt.Errorf("chown %s: %w", d.path, err)
		}
	}
	logf("setup-dirs complete")
	return nil
}

// ---------------------------------------------------------------------------
// Healthcheck: send a DNS query to 127.0.0.1:53 and verify we get a valid
// DNS response back. Uses CH TXT version.bind (always available on BIND).
//
// Accepts ANY valid DNS response (QR=1), regardless of RCODE.
// Even with version "none" in config (RCODE=REFUSED), the QR bit proves
// the full DNS pipeline is processing queries.
//
// This is superior to TCP connect (only proves socket is open) or PID file
// check (only proves process exists).
// ---------------------------------------------------------------------------

func healthcheck() int {
	// Minimal DNS query: CH TXT version.bind
	// Header: ID=0xBE9D, QR=0, OPCODE=0, QDCOUNT=1
	// Question: \x07version\x04bind\x00, QTYPE=TXT(16), QCLASS=CH(3)
	query := []byte{
		0xBE, 0x9D, // ID
		0x00, 0x00, // Flags: standard query
		0x00, 0x01, // QDCOUNT: 1
		0x00, 0x00, // ANCOUNT: 0
		0x00, 0x00, // NSCOUNT: 0
		0x00, 0x00, // ARCOUNT: 0
		// QNAME: version.bind.
		0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n',
		0x04, 'b', 'i', 'n', 'd',
		0x00,       // root label
		0x00, 0x10, // QTYPE: TXT (16)
		0x00, 0x03, // QCLASS: CH  (3)
	}

	conn, err := net.DialTimeout("udp", dnsAddr, 2*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[healthcheck] dial %s: %v\n", dnsAddr, err)
		return 1
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	if _, err := conn.Write(query); err != nil {
		fmt.Fprintf(os.Stderr, "[healthcheck] write: %v\n", err)
		return 1
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[healthcheck] read: %v\n", err)
		return 1
	}
	if n < 4 {
		fmt.Fprintf(os.Stderr, "[healthcheck] response too short (%d bytes)\n", n)
		return 1
	}

	// Verify: response ID matches the query ID (0xBE9D)
	id := binary.BigEndian.Uint16(buf[0:2])
	if id != 0xBE9D {
		fmt.Fprintf(os.Stderr, "[healthcheck] unexpected response ID (0x%04x)\n", id)
		return 1
	}

	// Verify: QR bit set (bit 15 of flags word) = this is a response
	flags := binary.BigEndian.Uint16(buf[2:4])
	if flags>>15 != 1 {
		fmt.Fprintf(os.Stderr, "[healthcheck] not a DNS response (flags=0x%04x)\n", flags)
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// Entrypoint: validate config, ensure writable dirs, then exec named.
// ---------------------------------------------------------------------------

func entrypoint() error {
	conf := env("NAMED_CONF", defaultConf)

	// 1. Verify config file exists
	if !exists(conf) {
		return fmt.Errorf("config file %s not found -- is the /etc/bind volume mounted?", conf)
	}

	// 2. Ensure writable dirs for runtime data
	for _, dir := range []string{"/var/cache/bind", "/var/run/named", "/run/named"} {
		if err := ensureWritable(dir, namedUID, namedGID); err != nil {
			return err
		}
	}

	// 3. Config validation (named-checkconf)
	// Fatal on failure -- a broken config breaks all DNS for the homelab.
	checkconf := findBin("named-checkconf")
	if checkconf != "" {
		logf("Validating configuration...")
		if err := run(checkconf, conf); err != nil {
			return fmt.Errorf("named-checkconf failed: %w\nFix the configuration before starting BIND.", err)
		}
		logf("Configuration OK")
	} else {
		logf("named-checkconf not found, skipping validation")
	}

	// 4. Build exec args
	// If first arg is not "named", prepend it.
	// Handles VyOS passing raw arguments that override the Dockerfile CMD.
	args := os.Args[1:]
	if len(args) == 0 || (args[0] != "named" && args[0] != "/usr/sbin/named") {
		args = append([]string{"named"}, args...)
	}

	logf("Starting BIND: %v", args)
	return execCmd(args)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func findBin(name string) string {
	// Check common paths
	for _, p := range []string{
		"/usr/sbin/" + name,
		"/usr/bin/" + name,
		"/sbin/" + name,
		"/bin/" + name,
	} {
		if exists(p) {
			return p
		}
	}
	return ""
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func execCmd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no command specified")
	}
	bin := findBin(args[0])
	if bin == "" {
		// Try LookPath as fallback
		var err error
		bin, err = exec.LookPath(args[0])
		if err != nil {
			return fmt.Errorf("command not found: %s", args[0])
		}
	}
	return syscall.Exec(bin, args, os.Environ())
}

func ensureWritable(path string, uid, gid int) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Try to create it (might work if parent is writable)
			if mkErr := os.MkdirAll(path, 0755); mkErr == nil {
				_ = os.Chown(path, uid, gid)
				logf("created %s", path)
				return nil
			}
			return fmt.Errorf("%s does not exist and cannot be created: %w", path, err)
		}
		return fmt.Errorf("%s: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s exists but is not a directory", path)
	}

	// Fast path: try writing a temp file
	if writeOK(path) {
		return nil
	}

	// Slow path: attempt chown + retry
	logf("%s is not writable by uid %d, attempting chown to %d:%d", path, os.Getuid(), uid, gid)
	if chErr := chownRecursive(path, uid, gid); chErr == nil {
		if writeOK(path) {
			logf("fixed ownership of %s", path)
			return nil
		}
	}

	return fmt.Errorf(
		"%s is not writable by uid %d.\n"+
			"  Fix with: sudo chown -R %d:%d <host-path-mounted-to-%s>",
		path, os.Getuid(), uid, gid, path,
	)
}

func writeOK(dir string) bool {
	tmp, err := os.CreateTemp(dir, ".write-test-*")
	if err != nil {
		return false
	}
	name := tmp.Name()
	tmp.Close()
	os.Remove(name)
	return true
}

func chownRecursive(path string, uid, gid int) error {
	return filepath.Walk(path, func(name string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Chown(name, uid, gid)
	})
}

func logf(format string, a ...any) {
	fmt.Printf("[init] "+format+"\n", a...)
}
