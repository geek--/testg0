package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"os"
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
	Events      []Event `json:"events"`
}

var (
	reFailed = regexp.MustCompile(`Failed password for (invalid user )?(\S+) from ([0-9a-fA-F\.:]+) port (\d+) ssh2`)
	reAccept = regexp.MustCompile(`Accepted (publickey|password) for (\S+) from ([0-9a-fA-F\.:]+) port (\d+) ssh2(?:: (\S+)\s+(\S+))?`)
	// Ejemplo de línea:
	// 2025-12-08T08:54:37.490977+00:00 isov3 sudo:     root : TTY=pts/4 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/ls /root
	reSudoCmd = regexp.MustCompile(`sudo:\s+(\S+)\s*:\s+TTY=([^;]+);\s+PWD=([^;]+);\s+USER=([^;]+);\s+COMMAND=(.+)$`)
)

const authLogPath = "/var/log/auth.log"

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
