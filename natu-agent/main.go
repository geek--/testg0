package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hpcloud/tail"
)

type Event struct {
	Ts        time.Time              `json:"ts"`
	Source    string                 `json:"source"`
	EventType string                 `json:"event_type"`
	Severity  int                    `json:"severity"`
	Payload   map[string]interface{} `json:"payload"`
}

type BatchRequest struct {
	AgentSecret string  `json:"agent_secret"`
	Hostname    string  `json:"hostname,omitempty"`
	Events      []Event `json:"events"`
}

type SSHBan struct {
	IP       string     `json:"ip"`
	Jail     string     `json:"jail"`
	BannedAt *time.Time `json:"banned_at,omitempty"`
	Source   string     `json:"source,omitempty"`
	Reason   string     `json:"reason,omitempty"`
}

type SSHBanSyncRequest struct {
	AgentSecret string   `json:"agent_secret"`
	Hostname    string   `json:"hostname"`
	Bans        []SSHBan `json:"bans"`
}

type SSHBanListResponse struct {
	GeneratedAt time.Time `json:"generated_at"`
	Bans        []SSHBan  `json:"bans"`
}

var (
	reFailed = regexp.MustCompile(`Failed password for (invalid user )?(\S+) from ([0-9a-fA-F\.:]+) port (\d+) ssh2`)
	reAccept = regexp.MustCompile(`Accepted (publickey|password) for (\S+) from ([0-9a-fA-F\.:]+) port (\d+) ssh2(?:: (\S+)\s+(\S+))?`)
	// Ejemplo de línea:
	// 2025-12-08T08:54:37.490977+00:00 isov3 sudo:     root : TTY=pts/4 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/ls /root
	reSudoCmd = regexp.MustCompile(`sudo:\s+(\S+)\s*:\s+TTY=([^;]+);\s+PWD=([^;]+);\s+USER=([^;]+);\s+COMMAND=(.+)$`)
	reBanLine = regexp.MustCompile(`^([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2},[0-9]{3}).*Ban ([0-9a-fA-F\.:]+)`) // fail2ban log
)

const authLogPath = "/var/log/auth.log"
const fail2banLogPath = "/var/log/fail2ban.log"

func main() {
	serverURL := os.Getenv("NATU_SERVER_URL")
	if serverURL == "" {
		serverURL = "http://127.0.0.1:5010"
	}
	secret := os.Getenv("NATU_AGENT_SECRET")
	if secret == "" {
		log.Fatal("NATU_AGENT_SECRET no está definido")
	}

	log.Printf("natu-agent empezando. Enviando a %s", serverURL)

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

	// Arranca el endpoint local para exponer los bans actuales
	go startHTTPServer()

	t, err := tail.TailFile(authLogPath, tail.Config{
		Follow:    true,
		ReOpen:    true,
		Logger:    tail.DiscardingLogger,
		MustExist: true,
		Poll:      true,
	})
	if err != nil {
		log.Fatalf("Error abriendo %s: %v", authLogPath, err)
	}

	client := &http.Client{Timeout: 5 * time.Second}

	// Sincronización periódica de bans activos hacia natu-core
	go startBanSyncLoop(client, serverURL, secret, hostname)

	for line := range t.Lines {
		if line == nil {
			continue
		}
		ev := parseAuthLine(line.Text)
		if ev == nil {
			continue
		}

		req := BatchRequest{
			AgentSecret: secret,
			Hostname:    hostname,
			Events:      []Event{*ev},
		}

		b, err := json.Marshal(req)
		if err != nil {
			log.Printf("Error serializando evento: %v", err)
			continue
		}

		resp, err := client.Post(serverURL+"/api/v1/events/batch", "application/json", bytes.NewReader(b))
		if err != nil {
			log.Printf("Error enviando evento: %v", err)
			continue
		}
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Printf("Error enviando evento: http %d", resp.StatusCode)
			continue
		}

		switch ev.EventType {
		case "ssh_failed_login":
			log.Printf("Evento enviado (failed): %s", line.Text)
		case "ssh_login_success":
			log.Printf("Evento enviado (success): %s", line.Text)
		case "sudo_command":
			log.Printf("Evento enviado (sudo): %s", line.Text)
		}
	}
}

func startHTTPServer() {
	addr := os.Getenv("NATU_AGENT_HTTP_ADDR")
	if addr == "" {
		addr = ":5011"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/ssh/bans", handleLocalBans)

	log.Printf("natu-agent escuchando bans en %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Printf("HTTP server de natu-agent finalizó: %v", err)
	}
}

func handleLocalBans(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "solo GET", http.StatusMethodNotAllowed)
		return
	}

	bans, err := collectCurrentBans()
	if err != nil {
		log.Printf("error listando bans: %v", err)
		http.Error(w, "error obteniendo bans", http.StatusInternalServerError)
		return
	}

	resp := SSHBanListResponse{
		GeneratedAt: time.Now().UTC(),
		Bans:        bans,
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}

func startBanSyncLoop(client *http.Client, serverURL, secret, hostname string) {
	syncEvery := 60 * time.Second
	if v := os.Getenv("NATU_AGENT_BAN_SYNC_SECONDS"); v != "" {
		if iv, err := strconv.Atoi(v); err == nil && iv >= 15 {
			syncEvery = time.Duration(iv) * time.Second
		}
	}

	syncOnce := func() {
		bans, err := collectCurrentBans()
		if err != nil {
			log.Printf("error recopilando bans: %v", err)
			return
		}

		payload := SSHBanSyncRequest{AgentSecret: secret, Hostname: hostname, Bans: bans}
		b, err := json.Marshal(payload)
		if err != nil {
			log.Printf("error serializando bans: %v", err)
			return
		}

		resp, err := client.Post(serverURL+"/api/v1/ssh_bans", "application/json", bytes.NewReader(b))
		if err != nil {
			log.Printf("error enviando bans: %v", err)
			return
		}
		_ = resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Printf("error enviando bans: http %d", resp.StatusCode)
			return
		}

		log.Printf("bans sincronizados (%d IPs)", len(bans))
	}

	// Primer sync inmediato
	syncOnce()

	ticker := time.NewTicker(syncEvery)
	go func() {
		for range ticker.C {
			syncOnce()
		}
	}()
}

func collectCurrentBans() ([]SSHBan, error) {
	statusCmd := exec.Command("/usr/bin/fail2ban-client", "status", "sshd")
	out, err := statusCmd.Output()
	if err != nil {
		return nil, err
	}

	ips := parseBannedIPs(string(out))
	timestamps := parseBanTimestamps()

	var bans []SSHBan
	for _, ip := range ips {
		ban := SSHBan{
			IP:     ip,
			Jail:   "sshd",
			Source: "fail2ban",
			Reason: "active ban",
		}

		if ts, ok := timestamps[ip]; ok {
			ban.BannedAt = &ts
		}

		bans = append(bans, ban)
	}

	return bans, nil
}

func parseBannedIPs(out string) []string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "Banned IP list:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) < 2 {
				continue
			}
			fields := strings.Fields(parts[1])
			return fields
		}
	}
	return []string{}
}

func parseBanTimestamps() map[string]time.Time {
	cmd := exec.Command("tail", "-n", "400", fail2banLogPath)
	out, err := cmd.Output()
	if err != nil {
		return map[string]time.Time{}
	}

	tsMap := make(map[string]time.Time)
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	layout := "2006-01-02 15:04:05,000"

	for scanner.Scan() {
		line := scanner.Text()
		m := reBanLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		ts, err := time.ParseInLocation(layout, m[1], time.Local)
		if err != nil {
			continue
		}

		ip := m[2]
		tsMap[ip] = ts.UTC()
	}

	return tsMap
}

func parseAuthLine(line string) *Event {
	// Todas tus líneas tienen timestamp inicial RFC3339Nano, igual que en SSH:
	// 2025-12-08T08:54:37.490977+00:00 isov3 ...
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 {
		return nil
	}
	tsStr := parts[0]
	rest := parts[1]

	ts, err := time.Parse(time.RFC3339Nano, tsStr)
	if err != nil {
		ts = time.Now().UTC()
	}

	// 1) Rama SSH (igual que antes, pero usando 'rest' en vez de 'line')
	if strings.Contains(rest, "sshd[") {
		var msg string
		if idx := strings.Index(rest, "sshd["); idx != -1 {
			if colon := strings.Index(rest[idx:], ":"); colon != -1 {
				msg = strings.TrimSpace(rest[idx+colon+1:])
			} else {
				msg = strings.TrimSpace(rest[idx:])
			}
		} else {
			msg = rest
		}

		if m := reFailed.FindStringSubmatch(msg); m != nil {
			username := m[2]
			remoteIP := m[3]
			portStr := m[4]
			dstPort, _ := strconv.Atoi(portStr)

			isRoot := username == "root"

			payload := map[string]interface{}{
				"raw_line":    line,
				"username":    username,
				"remote_ip":   remoteIP,
				"auth_method": "password",
				"is_root":     isRoot,
				"dst_port":    dstPort,
			}

			return &Event{
				Ts:        ts,
				Source:    "auth",
				EventType: "ssh_failed_login",
				Severity:  3,
				Payload:   payload,
			}
		}

		if m := reAccept.FindStringSubmatch(msg); m != nil {
			authMethod := m[1]
			username := m[2]
			remoteIP := m[3]
			portStr := m[4]
			dstPort, _ := strconv.Atoi(portStr)
			keyType := ""
			keyFingerprint := ""

			if len(m) >= 7 {
				if m[5] != "" {
					keyType = m[5]
				}
				if m[6] != "" {
					keyFingerprint = m[6]
				}
			}

			isRoot := username == "root"

			payload := map[string]interface{}{
				"raw_line":    line,
				"username":    username,
				"remote_ip":   remoteIP,
				"auth_method": authMethod,
				"is_root":     isRoot,
				"dst_port":    dstPort,
			}
			if keyType != "" {
				payload["key_type"] = keyType
			}
			if keyFingerprint != "" {
				payload["key_fingerprint"] = keyFingerprint
			}

			return &Event{
				Ts:        ts,
				Source:    "auth",
				EventType: "ssh_login_success",
				Severity:  2,
				Payload:   payload,
			}
		}

		// Si era una línea de sshd pero no encajó en failed/success, la ignoramos
		return nil
	}

	// 2) Rama sudo COMMAND=
	if strings.Contains(rest, "sudo:") {
		// Queremos la parte desde "sudo:" en adelante
		idx := strings.Index(rest, "sudo:")
		if idx == -1 {
			return nil
		}
		msg := strings.TrimSpace(rest[idx:]) // "sudo:     root : TTY=... ; PWD=... ; USER=... ; COMMAND=..."

		// Ignorar las líneas de pam_unix(sudo:session)
		if strings.Contains(msg, "pam_unix(sudo:session)") {
			return nil
		}

		m := reSudoCmd.FindStringSubmatch(msg)
		if m == nil {
			return nil
		}

		sudoUser := m[1]
		tty := strings.TrimSpace(m[2])
		pwd := strings.TrimSpace(m[3])
		targetUser := strings.TrimSpace(m[4])
		command := strings.TrimSpace(m[5])

		payload := map[string]interface{}{
			"raw_line":    line,
			"sudo_user":   sudoUser,
			"target_user": targetUser,
			"tty":         tty,
			"pwd":         pwd,
			"command":     command,
		}

		if targetUser == "root" {
			payload["is_target_root"] = true
		}
		if sudoUser == "root" {
			payload["is_sudo_root"] = true
		}

		return &Event{
			Ts:        ts,
			Source:    "auth",
			EventType: "sudo_command",
			Severity:  3,
			Payload:   payload,
		}
	}

	// 3) Otras líneas de auth.log que no sean sshd ni sudo command => las ignoramos
	return nil
}
