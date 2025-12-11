package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ----------------------------
// Tipos base
// ----------------------------

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

type Server struct {
	db *pgxpool.Pool
}

// ----------------------------
// Resumen SSH
// ----------------------------

type SSHHostSummary struct {
	Hostname string `json:"hostname"`
	Failed   int    `json:"failed"`
	Success  int    `json:"success"`
}

type SSHTopIP struct {
	RemoteIP string `json:"remote_ip"`
	Failed   int    `json:"failed"`
}

type SSHTopUser struct {
	Username string `json:"username"`
	Failed   int    `json:"failed"`
	Success  int    `json:"success"`
}

type SSHSummaryResponse struct {
	WindowMinutes int              `json:"window_minutes"`
	GeneratedAt   time.Time        `json:"generated_at"`
	Hosts         []SSHHostSummary `json:"hosts"`
	TopIPs        []SSHTopIP       `json:"top_ips"`
	TopUsers      []SSHTopUser     `json:"top_users"`
}

// ----------------------------
// SSH alerts (fuerza bruta)
// ----------------------------

type SSHAlert struct {
	ID            int64     `json:"id"`
	CreatedAt     time.Time `json:"created_at"`
	Hostname      string    `json:"hostname"`
	RemoteIP      string    `json:"remote_ip"`
	Username      string    `json:"username,omitempty"`
	FailedCount   int       `json:"failed_count"`
	WindowMinutes int       `json:"window_minutes"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	Status        string    `json:"status"`
	Rule          string    `json:"rule,omitempty"`
	Severity      string    `json:"severity,omitempty"`
	Message       string    `json:"message,omitempty"`
}

type SSHAlertsResponse struct {
	WindowMinutes int        `json:"window_minutes"`
	Limit         int        `json:"limit"`
	GeneratedAt   time.Time  `json:"generated_at"`
	Alerts        []SSHAlert `json:"alerts"`
}

type SSHAlertUpdateRequest struct {
	Status string `json:"status"`
}

// ----------------------------
// SSH suspicious logins (brute-force exitoso)
// ----------------------------

type SSHSuspiciousLogin struct {
	ID                       int64     `json:"id"`
	CreatedAt                time.Time `json:"created_at"`
	Hostname                 string    `json:"hostname"`
	Username                 string    `json:"username"`
	RemoteIP                 string    `json:"remote_ip"`
	FailedCountBeforeSuccess int       `json:"failed_count_before_success"`
	WindowMinutes            int       `json:"window_minutes"`
	FirstFailedAt            time.Time `json:"first_failed_at"`
	SuccessAt                time.Time `json:"success_at"`
	Status                   string    `json:"status"`
}

type SSHSuspiciousLoginsResponse struct {
	WindowMinutes int                  `json:"window_minutes"`
	Limit         int                  `json:"limit"`
	GeneratedAt   time.Time            `json:"generated_at"`
	Items         []SSHSuspiciousLogin `json:"items"`
}

type SSHSuspiciousLoginUpdateRequest struct {
	Status string `json:"status"`
}

// ----------------------------
// SSH timeline
// ----------------------------

type SSHTimelineEvent struct {
	Ts         time.Time `json:"ts"`
	Hostname   string    `json:"hostname"`
	EventType  string    `json:"event_type"`
	Username   string    `json:"username"`
	RemoteIP   string    `json:"remote_ip"`
	AuthMethod string    `json:"auth_method,omitempty"`
	IsRoot     bool      `json:"is_root"`
	DstPort    int       `json:"dst_port,omitempty"`
	RawLine    string    `json:"raw_line"`
}

type SSHTimelineResponse struct {
	IP            string             `json:"ip"`
	Username      string             `json:"username,omitempty"`
	WindowMinutes int                `json:"window_minutes"`
	Limit         int                `json:"limit"`
	GeneratedAt   time.Time          `json:"generated_at"`
	Events        []SSHTimelineEvent `json:"events"`
}

// ----------------------------
// Sudo timeline
// ----------------------------

type SudoTimelineEvent struct {
	Ts           time.Time `json:"ts"`
	Hostname     string    `json:"hostname"`
	SudoUser     string    `json:"sudo_user"`
	TargetUser   string    `json:"target_user"`
	TTY          string    `json:"tty"`
	Pwd          string    `json:"pwd"`
	Command      string    `json:"command"`
	RemoteIP     string    `json:"remote_ip,omitempty"`
	IsSudoRoot   bool      `json:"is_sudo_root"`
	IsTargetRoot bool      `json:"is_target_root"`
	RawLine      string    `json:"raw_line"`
}

type SudoTimelineResponse struct {
	SudoUser      string              `json:"sudo_user,omitempty"`
	TargetUser    string              `json:"target_user,omitempty"`
	WindowMinutes int                 `json:"window_minutes"`
	Limit         int                 `json:"limit"`
	GeneratedAt   time.Time           `json:"generated_at"`
	Events        []SudoTimelineEvent `json:"events"`
}

// ----------------------------
// Sudo alerts (comandos peligrosos)
// ----------------------------

type SudoAlert struct {
	ID            int64     `json:"id"`
	CreatedAt     time.Time `json:"created_at"`
	Hostname      string    `json:"hostname"`
	SudoUser      string    `json:"sudo_user"`
	TargetUser    string    `json:"target_user"`
	RemoteIP      string    `json:"remote_ip"`
	TTY           string    `json:"tty"`
	Pwd           string    `json:"pwd"`
	Command       string    `json:"command"`
	WindowMinutes int       `json:"window_minutes"`
	SudoTs        time.Time `json:"sudo_ts"`
	Status        string    `json:"status"`
}

type SudoAlertsResponse struct {
	WindowMinutes int         `json:"window_minutes"`
	Limit         int         `json:"limit"`
	GeneratedAt   time.Time   `json:"generated_at"`
	Alerts        []SudoAlert `json:"alerts"`
}

type SudoAlertUpdateRequest struct {
	Status string `json:"status"`
}

// ----------------------------
// SSH bans (Fail2ban/ipset)
// ----------------------------

type SSHBan struct {
	Hostname string     `json:"hostname"`
	IP       string     `json:"ip"`
	Jail     string     `json:"jail"`
	BannedAt *time.Time `json:"banned_at,omitempty"`
	Reason   string     `json:"reason,omitempty"`
	Source   string     `json:"source,omitempty"`
	SyncedAt time.Time  `json:"synced_at"`
}

type SSHBanSyncRequest struct {
	AgentSecret string `json:"agent_secret"`
	Bans        []struct {
		IP       string     `json:"ip"`
		Jail     string     `json:"jail"`
		BannedAt *time.Time `json:"banned_at,omitempty"`
		Reason   string     `json:"reason,omitempty"`
		Source   string     `json:"source,omitempty"`
	} `json:"bans"`
}

type SSHBanResponse struct {
	WindowMinutes int       `json:"window_minutes"`
	GeneratedAt   time.Time `json:"generated_at"`
	Bans          []SSHBan  `json:"bans"`
}

// ----------------------------
// Constantes de reglas
// ----------------------------

const (
	SSHAlertWindowMinutes         = 60
	SSHAlertFailedThreshold       = 5
	SuspiciousWindowMinutes       = 15
	SuspiciousFailedBeforeSuccess = 3

	SudoAlertWindowMinutes = 60
)

// lista naive de comandos sudo "peligrosos"
var sudoDangerousSubstrings = []string{
	"bash -c",
	"sh -c",
	" nc ",
	"ncat ",
	"socat",
	"useradd",
	"usermod",
	"passwd",
	"chmod 777",
	"chown ",
	"chgrp ",
	"curl ",
	"wget ",
	"scp ",
	"sftp ",
}

// ----------------------------
// main
// ----------------------------

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL no está definido")
	}

	ctx := context.Background()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		log.Fatalf("Error creando pool: %v", err)
	}
	defer pool.Close()

	if err := ensureBanTable(ctx, pool); err != nil {
		log.Fatalf("Error asegurando tabla ssh_bans_state: %v", err)
	}

	srv := &Server{db: pool}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/events/batch", srv.handleBatchEvents)
	mux.HandleFunc("/api/v1/ssh_summary", srv.handleSSHSummary)
	mux.HandleFunc("/api/v1/ssh_activity", srv.handleSSHActivity)
	mux.HandleFunc("/api/v1/ssh_alerts", srv.handleSSHAlerts)
	mux.HandleFunc("/api/v1/ssh_alerts/", srv.handleSSHAlerts)
	mux.HandleFunc("/api/v1/ssh_suspicious_logins", srv.handleSSHSuspiciousLogins)
	mux.HandleFunc("/api/v1/ssh_suspicious_logins/", srv.handleSSHSuspiciousLogins)
	mux.HandleFunc("/api/v1/ssh_timeline", srv.handleSSHTimeline)
	mux.HandleFunc("/api/v1/sudo_timeline", srv.handleSudoTimeline)
	mux.HandleFunc("/api/v1/sudo_alerts", srv.handleSudoAlerts)
	mux.HandleFunc("/api/v1/sudo_alerts/", srv.handleSudoAlerts)
	mux.HandleFunc("/api/v1/ssh_bans", srv.handleSSHBans)

	// Workers
	srv.startSSHAlertWorker(SSHAlertWindowMinutes, SSHAlertFailedThreshold)
	srv.startSSHSuspiciousLoginWorker(SuspiciousWindowMinutes, SuspiciousFailedBeforeSuccess)
	srv.startSudoAlertWorker(SudoAlertWindowMinutes)

	addr := ":5010"

	log.Printf("natu-core escuchando en %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Error en servidor HTTP: %v", err)
	}
}

func ensureBanTable(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
        CREATE TABLE IF NOT EXISTS ssh_bans_state (
            agent_id uuid REFERENCES agents(id) ON DELETE CASCADE,
            ip text NOT NULL,
            jail text NOT NULL DEFAULT 'sshd',
            banned_at timestamptz,
            reason text,
            source text,
            synced_at timestamptz NOT NULL DEFAULT now(),
            PRIMARY KEY (agent_id, ip, jail)
        );
    `)
	return err
}

// ----------------------------------------------------
// Ingesta de eventos (batch)
// ----------------------------------------------------

func (s *Server) handleBatchEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "solo POST", http.StatusMethodNotAllowed)
		return
	}

	var req BatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "JSON inválido", http.StatusBadRequest)
		return
	}
	if req.AgentSecret == "" || len(req.Events) == 0 {
		http.Error(w, "agent_secret y events requeridos", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	var agentID string
	err := s.db.QueryRow(ctx, `
        SELECT id::text
        FROM agents
        WHERE secret = $1
    `, req.AgentSecret).Scan(&agentID)
	if err != nil {
		log.Printf("❌ Error buscando agente: secret='%s', err=%v", req.AgentSecret, err)
		http.Error(w, "agente no encontrado o secret inválido", http.StatusUnauthorized)
		return
	}

	_, _ = s.db.Exec(ctx, `UPDATE agents SET last_seen = now() WHERE id = $1`, agentID)

	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "error iniciando transacción", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(ctx)

	for _, ev := range req.Events {
		if ev.Ts.IsZero() {
			ev.Ts = time.Now().UTC()
		}
		if ev.Severity == 0 {
			ev.Severity = 1
		}
		payloadBytes, err := json.Marshal(ev.Payload)
		if err != nil {
			http.Error(w, "payload inválido", http.StatusBadRequest)
			return
		}

		_, err = tx.Exec(ctx, `
            INSERT INTO raw_events (agent_id, ts, source, event_type, severity, payload)
            VALUES ($1, $2, $3, $4, $5, $6::jsonb)
        `, agentID, ev.Ts, ev.Source, ev.EventType, ev.Severity, string(payloadBytes))
		if err != nil {
			http.Error(w, "error insertando eventos", http.StatusInternalServerError)
			return
		}
	}

	if err := tx.Commit(ctx); err != nil {
		http.Error(w, "error commit", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// ----------------------------------------------------
// Bans SSH (Fail2ban/ipset)
// ----------------------------------------------------

func (s *Server) handleSSHBans(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.handlePostSSHBans(w, r)
	case http.MethodGet:
		s.handleGetSSHBans(w, r)
	default:
		http.Error(w, "solo GET/POST", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handlePostSSHBans(w http.ResponseWriter, r *http.Request) {
	var req SSHBanSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "JSON inválido", http.StatusBadRequest)
		return
	}

	if req.AgentSecret == "" {
		http.Error(w, "agent_secret requerido", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	var agentID string
	err := s.db.QueryRow(ctx, `
        SELECT id::text
        FROM agents
        WHERE secret = $1
    `, req.AgentSecret).Scan(&agentID)
	if err != nil {
		http.Error(w, "agente no encontrado o secret inválido", http.StatusUnauthorized)
		return
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		http.Error(w, "error iniciando transacción", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM ssh_bans_state WHERE agent_id = $1`, agentID); err != nil {
		http.Error(w, "error limpiando bans previos", http.StatusInternalServerError)
		return
	}

	for _, ban := range req.Bans {
		if ban.IP == "" {
			continue
		}

		jail := ban.Jail
		if jail == "" {
			jail = "sshd"
		}

		_, err := tx.Exec(ctx, `
            INSERT INTO ssh_bans_state (agent_id, ip, jail, banned_at, reason, source, synced_at)
            VALUES ($1, $2, $3, $4, $5, $6, now())
        `, agentID, ban.IP, jail, ban.BannedAt, ban.Reason, ban.Source)
		if err != nil {
			http.Error(w, "error guardando bans", http.StatusInternalServerError)
			return
		}
	}

	if err := tx.Commit(ctx); err != nil {
		http.Error(w, "error commit bans", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) handleGetSSHBans(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	minStr := q.Get("minutes")
	windowMinutes := 1440
	if minStr != "" {
		if v, err := strconv.Atoi(minStr); err == nil && v > 0 && v <= 10080 {
			windowMinutes = v
		}
	}

	ctx := r.Context()
	now := time.Now().UTC()

	rows, err := s.db.Query(ctx, `
        SELECT b.ip, b.jail, b.banned_at, b.reason, b.source, b.synced_at, a.hostname
        FROM ssh_bans_state b
        JOIN agents a ON b.agent_id = a.id
        WHERE b.synced_at >= now() - ($1::int || ' minutes')::interval
        ORDER BY COALESCE(b.banned_at, b.synced_at) DESC;
    `, windowMinutes)
	if err != nil {
		http.Error(w, "error consultando bans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var bans []SSHBan
	for rows.Next() {
		var b SSHBan
		if err := rows.Scan(&b.IP, &b.Jail, &b.BannedAt, &b.Reason, &b.Source, &b.SyncedAt, &b.Hostname); err != nil {
			http.Error(w, "error leyendo bans", http.StatusInternalServerError)
			return
		}
		bans = append(bans, b)
	}

	if rows.Err() != nil {
		http.Error(w, "error final leyendo bans", http.StatusInternalServerError)
		return
	}

	if bans == nil {
		bans = []SSHBan{}
	}

	resp := SSHBanResponse{
		WindowMinutes: windowMinutes,
		GeneratedAt:   now,
		Bans:          bans,
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(resp); err != nil {
		http.Error(w, "error serializando respuesta", http.StatusInternalServerError)
		return
	}
}

// ----------------------------------------------------
// Resumen SSH
// ----------------------------------------------------

func (s *Server) handleSSHSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "solo GET", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	minStr := q.Get("minutes")
	windowMinutes := 60
	if minStr != "" {
		if v, err := strconv.Atoi(minStr); err == nil && v > 0 && v <= 1440 {
			windowMinutes = v
		}
	}

	ctx := r.Context()
	now := time.Now().UTC()

	var hosts []SSHHostSummary
	rows, err := s.db.Query(ctx, `
        SELECT a.hostname,
               COALESCE(SUM(CASE WHEN e.event_type = 'ssh_failed_login'  THEN 1 ELSE 0 END), 0) AS failed,
               COALESCE(SUM(CASE WHEN e.event_type = 'ssh_login_success' THEN 1 ELSE 0 END), 0) AS success
        FROM raw_events e
        JOIN agents a ON e.agent_id = a.id
        WHERE e.source = 'auth'
          AND e.event_type IN ('ssh_failed_login', 'ssh_login_success')
          AND e.ts >= now() - ($1::int || ' minutes')::interval
        GROUP BY a.hostname
        ORDER BY a.hostname;
    `, windowMinutes)
	if err != nil {
		log.Printf("Error consultando resumen por host: %v", err)
		http.Error(w, "error consultando resumen por host", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var h SSHHostSummary
		if err := rows.Scan(&h.Hostname, &h.Failed, &h.Success); err != nil {
			log.Printf("Error escaneando host: %v", err)
			http.Error(w, "error leyendo resumen por host", http.StatusInternalServerError)
			return
		}
		hosts = append(hosts, h)
	}
	if rows.Err() != nil {
		log.Printf("Error final en rows host: %v", rows.Err())
		http.Error(w, "error leyendo resumen por host", http.StatusInternalServerError)
		return
	}

	if hosts == nil {
		hosts = []SSHHostSummary{}
	}

	var topIPs []SSHTopIP
	rows, err = s.db.Query(ctx, `
        SELECT
            e.payload->>'remote_ip' AS remote_ip,
            COUNT(*) AS failed_count
        FROM raw_events e
        WHERE e.source = 'auth'
          AND e.event_type = 'ssh_failed_login'
          AND e.ts >= now() - ($1::int || ' minutes')::interval
          AND e.payload ? 'remote_ip'
        GROUP BY remote_ip
        ORDER BY failed_count DESC
        LIMIT 10;
    `, windowMinutes)
	if err != nil {
		log.Printf("Error consultando top IPs: %v", err)
		http.Error(w, "error consultando top IPs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var ip SSHTopIP
		if err := rows.Scan(&ip.RemoteIP, &ip.Failed); err != nil {
			log.Printf("Error escaneando top IP: %v", err)
			http.Error(w, "error leyendo top IPs", http.StatusInternalServerError)
			return
		}
		topIPs = append(topIPs, ip)
	}
	if rows.Err() != nil {
		log.Printf("Error final en rows IPs: %v", rows.Err())
		http.Error(w, "error leyendo top IPs", http.StatusInternalServerError)
		return
	}

	if topIPs == nil {
		topIPs = []SSHTopIP{}
	}

	var topUsers []SSHTopUser
	rows, err = s.db.Query(ctx, `
        SELECT
            e.payload->>'username' AS username,
            COUNT(*) FILTER (WHERE e.event_type = 'ssh_failed_login')  AS failed_count,
            COUNT(*) FILTER (WHERE e.event_type = 'ssh_login_success') AS success_count
        FROM raw_events e
        WHERE e.source = 'auth'
          AND e.event_type IN ('ssh_failed_login', 'ssh_login_success')
          AND e.ts >= now() - ($1::int || ' minutes')::interval
          AND e.payload ? 'username'
        GROUP BY username
        ORDER BY failed_count DESC, success_count DESC
        LIMIT 10;
    `, windowMinutes)
	if err != nil {
		log.Printf("Error consultando top usuarios: %v", err)
		http.Error(w, "error consultando top usuarios", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var u SSHTopUser
		if err := rows.Scan(&u.Username, &u.Failed, &u.Success); err != nil {
			log.Printf("Error escaneando top user: %v", err)
			http.Error(w, "error leyendo top usuarios", http.StatusInternalServerError)
			return
		}
		topUsers = append(topUsers, u)
	}
	if rows.Err() != nil {
		log.Printf("Error final en rows usuarios: %v", rows.Err())
		http.Error(w, "error leyendo top usuarios", http.StatusInternalServerError)
		return
	}

	if topUsers == nil {
		topUsers = []SSHTopUser{}
	}

	resp := SSHSummaryResponse{
		WindowMinutes: windowMinutes,
		GeneratedAt:   now,
		Hosts:         hosts,
		TopIPs:        topIPs,
		TopUsers:      topUsers,
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(resp); err != nil {
		log.Printf("Error serializando respuesta: %v", err)
	}
}

// ----------------------------------------------------
// Worker de alertas SSH (fuerza bruta)
// ----------------------------------------------------

func (s *Server) startSSHAlertWorker(windowMinutes int, threshold int) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := s.runSSHAlertScan(ctx, windowMinutes, threshold); err != nil {
				log.Printf("Error en SSHAlertWorker: %v", err)
			}
			cancel()
		}
	}()
}

func (s *Server) runSSHAlertScan(ctx context.Context, windowMinutes int, threshold int) error {
	rows, err := s.db.Query(ctx, `
        SELECT
            a.id::text       AS agent_id,
            a.hostname       AS hostname,
            e.payload->>'remote_ip' AS remote_ip,
            COUNT(*)         AS failed_count,
            MIN(e.ts)        AS first_seen,
            MAX(e.ts)        AS last_seen
        FROM raw_events e
        JOIN agents a ON e.agent_id = a.id
        WHERE e.source = 'auth'
          AND e.event_type = 'ssh_failed_login'
          AND e.ts >= now() - ($1::int || ' minutes')::interval
          AND e.payload ? 'remote_ip'
        GROUP BY a.id, a.hostname, remote_ip
        HAVING COUNT(*) >= $2
        ORDER BY failed_count DESC;
    `, windowMinutes, threshold)
	if err != nil {
		return err
	}
	defer rows.Close()

	type candidate struct {
		AgentID     string
		Hostname    string
		RemoteIP    string
		FailedCount int
		FirstSeen   time.Time
		LastSeen    time.Time
	}

	var cands []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.AgentID, &c.Hostname, &c.RemoteIP, &c.FailedCount, &c.FirstSeen, &c.LastSeen); err != nil {
			return err
		}
		cands = append(cands, c)
	}
	if rows.Err() != nil {
		return rows.Err()
	}

	for _, c := range cands {
		var exists bool
		err := s.db.QueryRow(ctx, `
            SELECT EXISTS (
                SELECT 1
                FROM ssh_alerts
                WHERE agent_id = $1
                  AND remote_ip = $2
                  AND created_at >= now() - ($3::int || ' minutes')::interval
            );
        `, c.AgentID, c.RemoteIP, windowMinutes).Scan(&exists)
		if err != nil {
			return err
		}

		if exists {
			continue
		}

		_, err = s.db.Exec(ctx, `
            INSERT INTO ssh_alerts (agent_id, hostname, remote_ip, failed_count, window_minutes, first_seen, last_seen, status)
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'new');
        `, c.AgentID, c.Hostname, c.RemoteIP, c.FailedCount, windowMinutes, c.FirstSeen, c.LastSeen)
		if err != nil {
			return err
		}

		log.Printf("⚠️  SSH alert creada: host=%s ip=%s failed=%d window=%dmin",
			c.Hostname, c.RemoteIP, c.FailedCount, windowMinutes)
	}

	return nil
}

// ----------------------------------------------------
// Worker brute-force exitoso (ssh_suspicious_logins)
// ----------------------------------------------------

func (s *Server) startSSHSuspiciousLoginWorker(windowMinutes int, threshold int) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := s.runSSHSuspiciousLoginScan(ctx, windowMinutes, threshold); err != nil {
				log.Printf("Error en SSH Suspicious Worker: %v", err)
			}
			cancel()
		}
	}()
}

func (s *Server) runSSHSuspiciousLoginScan(ctx context.Context, windowMinutes int, threshold int) error {
	rows, err := s.db.Query(ctx, `
        SELECT
            a.id::text                        AS agent_id,
            a.hostname                        AS hostname,
            se.payload->>'username'           AS username,
            se.payload->>'remote_ip'          AS remote_ip,
            se.ts                             AS success_ts,
            COUNT(fe.*)                       AS failed_count,
            MIN(fe.ts)                        AS first_failed_at
        FROM raw_events se
        JOIN agents a ON se.agent_id = a.id
        JOIN raw_events fe ON fe.agent_id = se.agent_id
            AND fe.source = 'auth'
            AND fe.event_type = 'ssh_failed_login'
            AND fe.payload->>'remote_ip' = se.payload->>'remote_ip'
            AND fe.ts BETWEEN se.ts - ($1::int || ' minutes')::interval AND se.ts
        WHERE se.source = 'auth'
          AND se.event_type = 'ssh_login_success'
          AND se.ts >= now() - ($1::int || ' minutes')::interval
        GROUP BY a.id, a.hostname, username, remote_ip, success_ts
        HAVING COUNT(fe.*) >= $2
        ORDER BY success_ts DESC;
    `, windowMinutes, threshold)
	if err != nil {
		return err
	}
	defer rows.Close()

	type cand struct {
		AgentID     string
		Hostname    string
		Username    string
		RemoteIP    string
		SuccessTs   time.Time
		FailedCount int
		FirstFailed time.Time
	}

	var cands []cand
	for rows.Next() {
		var c cand
		if err := rows.Scan(&c.AgentID, &c.Hostname, &c.Username, &c.RemoteIP, &c.SuccessTs, &c.FailedCount, &c.FirstFailed); err != nil {
			return err
		}
		cands = append(cands, c)
	}
	if rows.Err() != nil {
		return rows.Err()
	}

	for _, c := range cands {
		var exists bool
		err := s.db.QueryRow(ctx, `
            SELECT EXISTS (
                SELECT 1
                FROM ssh_suspicious_logins
                WHERE agent_id = $1
                  AND remote_ip = $2
                  AND username = $3
                  AND success_at = $4
            );
        `, c.AgentID, c.RemoteIP, c.Username, c.SuccessTs).Scan(&exists)
		if err != nil {
			return err
		}

		if exists {
			continue
		}

		_, err = s.db.Exec(ctx, `
            INSERT INTO ssh_suspicious_logins (
                agent_id, hostname, username, remote_ip,
                failed_count_before_success, window_minutes,
                first_failed_at, success_at, status
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'new');
        `, c.AgentID, c.Hostname, c.Username, c.RemoteIP, c.FailedCount, windowMinutes, c.FirstFailed, c.SuccessTs)
		if err != nil {
			return err
		}

		log.Printf("⚠️  SSH suspicious login: host=%s ip=%s user=%s failed_before=%d window=%dmin",
			c.Hostname, c.RemoteIP, c.Username, c.FailedCount, windowMinutes)
	}

	return nil
}

// ----------------------------------------------------
// Worker sudo_alerts (comandos peligrosos)
// ----------------------------------------------------

func isDangerousSudoCommand(cmd string) bool {
	lower := strings.ToLower(cmd)
	for _, sub := range sudoDangerousSubstrings {
		if strings.Contains(lower, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

func (s *Server) startSudoAlertWorker(windowMinutes int) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := s.runSudoAlertScan(ctx, windowMinutes); err != nil {
				log.Printf("Error en SudoAlertWorker: %v", err)
			}
			cancel()
		}
	}()
}

func (s *Server) runSudoAlertScan(ctx context.Context, windowMinutes int) error {
	rows, err := s.db.Query(ctx, `
        SELECT
            e.agent_id::text                 AS agent_id,
            a.hostname                       AS hostname,
            e.ts                             AS sudo_ts,
            e.payload->>'sudo_user'          AS sudo_user,
            e.payload->>'target_user'        AS target_user,
            COALESCE(e.payload->>'tty', '')  AS tty,
            COALESCE(e.payload->>'pwd', '')  AS pwd,
            COALESCE(e.payload->>'command', '') AS command,
            COALESCE(se.remote_ip, '')       AS remote_ip
        FROM raw_events e
        JOIN agents a ON e.agent_id = a.id
        LEFT JOIN LATERAL (
            SELECT se.payload->>'remote_ip' AS remote_ip
            FROM raw_events se
            WHERE se.agent_id = e.agent_id
              AND se.source = 'auth'
              AND se.event_type = 'ssh_login_success'
              AND se.ts <= e.ts
              AND se.payload ? 'remote_ip'
            ORDER BY se.ts DESC
            LIMIT 1
        ) se ON TRUE
        WHERE e.source = 'auth'
          AND e.event_type = 'sudo_command'
          AND e.ts >= now() - ($1::int || ' minutes')::interval;
    `, windowMinutes)
	if err != nil {
		return err
	}
	defer rows.Close()

	type cand struct {
		AgentID  string
		Hostname string
		SudoTs   time.Time
		SudoUser string
		Target   string
		TTY      string
		Pwd      string
		Command  string
		RemoteIP string
	}

	var cands []cand
	for rows.Next() {
		var c cand
		if err := rows.Scan(&c.AgentID, &c.Hostname, &c.SudoTs, &c.SudoUser, &c.Target, &c.TTY, &c.Pwd, &c.Command, &c.RemoteIP); err != nil {
			return err
		}
		cands = append(cands, c)
	}
	if rows.Err() != nil {
		return rows.Err()
	}

	for _, c := range cands {
		if !isDangerousSudoCommand(c.Command) {
			continue
		}

		var exists bool
		err := s.db.QueryRow(ctx, `
            SELECT EXISTS (
                SELECT 1
                FROM sudo_alerts
                WHERE agent_id = $1
                  AND sudo_user = $2
                  AND target_user = $3
                  AND command = $4
                  AND sudo_ts = $5
            );
        `, c.AgentID, c.SudoUser, c.Target, c.Command, c.SudoTs).Scan(&exists)
		if err != nil {
			return err
		}
		if exists {
			continue
		}

		_, err = s.db.Exec(ctx, `
            INSERT INTO sudo_alerts (
                agent_id, hostname, sudo_user, target_user, remote_ip,
                tty, pwd, command, window_minutes, sudo_ts, status
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'new');
        `, c.AgentID, c.Hostname, c.SudoUser, c.Target, c.RemoteIP, c.TTY, c.Pwd, c.Command, windowMinutes, c.SudoTs)
		if err != nil {
			return err
		}

		log.Printf("⚠️  SUDO alert creada: host=%s user=%s target=%s ip=%s cmd=%q",
			c.Hostname, c.SudoUser, c.Target, c.RemoteIP, c.Command)
	}

	return nil
}

// ----------------------------------------------------
// API ssh_alerts (GET + PATCH)
// ----------------------------------------------------

func (s *Server) handleSSHAlerts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleSSHAlertsGET(w, r)
	case http.MethodPatch:
		s.handleSSHAlertsPATCH(w, r)
	default:
		http.Error(w, "solo GET o PATCH", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSSHAlertsGET(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	status := q.Get("status")
	ip := q.Get("ip")
	host := q.Get("hostname")
	minStr := q.Get("minutes")
	limitStr := q.Get("limit")

	windowMinutes := 60
	if minStr != "" {
		if v, err := strconv.Atoi(minStr); err == nil && v > 0 && v <= 10080 {
			windowMinutes = v
		}
	}

	limit := 50
	if limitStr != "" {
		if v, err := strconv.Atoi(limitStr); err == nil && v > 0 && v <= 500 {
			limit = v
		}
	}

	ctx := r.Context()
	now := time.Now().UTC()

	query := `
SELECT
    sa.id,
    sa.created_at,
    sa.hostname,
    sa.remote_ip,
    COALESCE(meta.username, '') AS username,
    sa.failed_count,
    sa.window_minutes,
    sa.first_seen,
    sa.last_seen,
    sa.status,
    'ssh_bruteforce' AS rule,
    CASE
        WHEN sa.failed_count >= 20 THEN 'crítico'
        WHEN sa.failed_count >= 10 THEN 'alto'
        ELSE 'medio'
    END AS severity,
    format(
        'Multiples fallos SSH (%s intentos en %s min) desde %s',
        sa.failed_count,
        sa.window_minutes,
        sa.remote_ip
    ) AS message
FROM ssh_alerts sa
LEFT JOIN LATERAL (
    SELECT e.payload->>'username' AS username
    FROM raw_events e
    WHERE e.source = 'auth'
      AND e.event_type = 'ssh_failed_login'
      AND e.payload->>'remote_ip' = sa.remote_ip
      AND e.ts BETWEEN sa.first_seen AND sa.last_seen
    GROUP BY username
    ORDER BY COUNT(*) DESC, MAX(e.ts) DESC
    LIMIT 1
) meta ON TRUE
WHERE sa.created_at >= now() - ($1::int || ' minutes')::interval
`
	args := []any{windowMinutes}
	argPos := 2

	if status != "" {
		query += " AND status = $" + strconv.Itoa(argPos)
		args = append(args, status)
		argPos++
	}
	if ip != "" {
		query += " AND remote_ip = $" + strconv.Itoa(argPos)
		args = append(args, ip)
		argPos++
	}
	if host != "" {
		query += " AND hostname = $" + strconv.Itoa(argPos)
		args = append(args, host)
		argPos++
	}

	query += " ORDER BY created_at DESC LIMIT $" + strconv.Itoa(argPos)
	args = append(args, limit)

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		log.Printf("Error consultando ssh_alerts: %v", err)
		http.Error(w, "error consultando alertas", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var alerts []SSHAlert
	for rows.Next() {
		var a SSHAlert
		if err := rows.Scan(
			&a.ID,
			&a.CreatedAt,
			&a.Hostname,
			&a.RemoteIP,
			&a.Username,
			&a.FailedCount,
			&a.WindowMinutes,
			&a.FirstSeen,
			&a.LastSeen,
			&a.Status,
			&a.Rule,
			&a.Severity,
			&a.Message,
		); err != nil {
			log.Printf("Error escaneando alerta ssh: %v", err)
			http.Error(w, "error leyendo alertas", http.StatusInternalServerError)
			return
		}
		alerts = append(alerts, a)
	}
	if rows.Err() != nil {
		log.Printf("Error final en rows ssh_alerts: %v", rows.Err())
		http.Error(w, "error leyendo alertas", http.StatusInternalServerError)
		return
	}

	if alerts == nil {
		alerts = []SSHAlert{}
	}

	resp := SSHAlertsResponse{
		WindowMinutes: windowMinutes,
		Limit:         limit,
		GeneratedAt:   now,
		Alerts:        alerts,
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(resp); err != nil {
		log.Printf("Error serializando respuesta ssh_alerts: %v", err)
	}
}

func (s *Server) handleSSHAlertsPATCH(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	prefix := "/api/v1/ssh_alerts/"
	if !strings.HasPrefix(path, prefix) || len(path) <= len(prefix) {
		http.Error(w, "ruta inválida, use /api/v1/ssh_alerts/{id}", http.StatusBadRequest)
		return
	}
	idStr := strings.TrimPrefix(path, prefix)
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "id inválido", http.StatusBadRequest)
		return
	}

	var req SSHAlertUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "JSON inválido", http.StatusBadRequest)
		return
	}

	newStatus := strings.ToLower(strings.TrimSpace(req.Status))
	if newStatus == "" {
		http.Error(w, "status requerido", http.StatusBadRequest)
		return
	}
	if newStatus != "new" && newStatus != "ack" && newStatus != "closed" {
		http.Error(w, "status inválido (use new, ack o closed)", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	var a SSHAlert
	err = s.db.QueryRow(ctx, `
        WITH updated AS (
            UPDATE ssh_alerts sa
            SET status = $1
            WHERE id = $2
            RETURNING sa.*
        )
        SELECT
            u.id,
            u.created_at,
            u.hostname,
            u.remote_ip,
            COALESCE(meta.username, '') AS username,
            u.failed_count,
            u.window_minutes,
            u.first_seen,
            u.last_seen,
            u.status,
            'ssh_bruteforce' AS rule,
            CASE
                WHEN u.failed_count >= 20 THEN 'crítico'
                WHEN u.failed_count >= 10 THEN 'alto'
                ELSE 'medio'
            END AS severity,
            format(
                'Multiples fallos SSH (%s intentos en %s min) desde %s',
                u.failed_count,
                u.window_minutes,
                u.remote_ip
            ) AS message
        FROM updated u
        LEFT JOIN LATERAL (
            SELECT e.payload->>'username' AS username
            FROM raw_events e
            WHERE e.source = 'auth'
              AND e.event_type = 'ssh_failed_login'
              AND e.payload->>'remote_ip' = u.remote_ip
              AND e.ts BETWEEN u.first_seen AND u.last_seen
            GROUP BY username
            ORDER BY COUNT(*) DESC, MAX(e.ts) DESC
            LIMIT 1
        ) meta ON TRUE;
    `, newStatus, id).Scan(
		&a.ID,
		&a.CreatedAt,
		&a.Hostname,
		&a.RemoteIP,
		&a.Username,
		&a.FailedCount,
		&a.WindowMinutes,
		&a.FirstSeen,
		&a.LastSeen,
		&a.Status,
		&a.Rule,
		&a.Severity,
		&a.Message,
	)

	if err != nil {
		log.Printf("Error actualizando ssh_alert id=%d: %v", id, err)
		http.Error(w, "alerta no encontrada o error al actualizar", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(a); err != nil {
		log.Printf("Error serializando respuesta PATCH ssh_alert: %v", err)
	}
}

// ----------------------------------------------------
// API ssh_suspicious_logins (GET + PATCH)
// ----------------------------------------------------

func (s *Server) handleSSHSuspiciousLogins(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleSSHSuspiciousLoginsGET(w, r)
	case http.MethodPatch:
		s.handleSSHSuspiciousLoginsPATCH(w, r)
	default:
		http.Error(w, "solo GET o PATCH", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSSHSuspiciousLoginsGET(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	status := q.Get("status")
	ip := q.Get("ip")
	host := q.Get("hostname")
	username := q.Get("username")
	minStr := q.Get("minutes")
	limitStr := q.Get("limit")

	windowMinutes := 60
	if minStr != "" {
		if v, err := strconv.Atoi(minStr); err == nil && v > 0 && v <= 10080 {
			windowMinutes = v
		}
	}

	limit := 50
	if limitStr != "" {
		if v, err := strconv.Atoi(limitStr); err == nil && v > 0 && v <= 500 {
			limit = v
		}
	}

	ctx := r.Context()
	now := time.Now().UTC()

	query := `
        SELECT
            id,
            created_at,
            hostname,
            username,
            remote_ip,
            failed_count_before_success,
            window_minutes,
            first_failed_at,
            success_at,
            status
        FROM ssh_suspicious_logins
        WHERE created_at >= now() - ($1::int || ' minutes')::interval
    `
	args := []any{windowMinutes}
	argPos := 2

	if status != "" {
		query += " AND status = $" + strconv.Itoa(argPos)
		args = append(args, status)
		argPos++
	}
	if ip != "" {
		query += " AND remote_ip = $" + strconv.Itoa(argPos)
		args = append(args, ip)
		argPos++
	}
	if host != "" {
		query += " AND hostname = $" + strconv.Itoa(argPos)
		args = append(args, host)
		argPos++
	}
	if username != "" {
		query += " AND username = $" + strconv.Itoa(argPos)
		args = append(args, username)
		argPos++
	}

	query += " ORDER BY success_at DESC LIMIT $" + strconv.Itoa(argPos)
	args = append(args, limit)

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		log.Printf("Error consultando ssh_suspicious_logins: %v", err)
		http.Error(w, "error consultando ssh_suspicious_logins", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var items []SSHSuspiciousLogin
	for rows.Next() {
		var it SSHSuspiciousLogin
		if err := rows.Scan(
			&it.ID,
			&it.CreatedAt,
			&it.Hostname,
			&it.Username,
			&it.RemoteIP,
			&it.FailedCountBeforeSuccess,
			&it.WindowMinutes,
			&it.FirstFailedAt,
			&it.SuccessAt,
			&it.Status,
		); err != nil {
			log.Printf("Error escaneando ssh_suspicious_login: %v", err)
			http.Error(w, "error leyendo ssh_suspicious_logins", http.StatusInternalServerError)
			return
		}
		items = append(items, it)
	}
	if rows.Err() != nil {
		log.Printf("Error final en rows ssh_suspicious_logins: %v", rows.Err())
		http.Error(w, "error leyendo ssh_suspicious_logins", http.StatusInternalServerError)
		return
	}

	if items == nil {
		items = []SSHSuspiciousLogin{}
	}

	resp := SSHSuspiciousLoginsResponse{
		WindowMinutes: windowMinutes,
		Limit:         limit,
		GeneratedAt:   now,
		Items:         items,
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(resp); err != nil {
		log.Printf("Error serializando respuesta ssh_suspicious_logins: %v", err)
	}
}

func (s *Server) handleSSHSuspiciousLoginsPATCH(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	prefix := "/api/v1/ssh_suspicious_logins/"
	if !strings.HasPrefix(path, prefix) || len(path) <= len(prefix) {
		http.Error(w, "ruta inválida, use /api/v1/ssh_suspicious_logins/{id}", http.StatusBadRequest)
		return
	}
	idStr := strings.TrimPrefix(path, prefix)
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "id inválido", http.StatusBadRequest)
		return
	}

	var req SSHSuspiciousLoginUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "JSON inválido", http.StatusBadRequest)
		return
	}

	newStatus := strings.ToLower(strings.TrimSpace(req.Status))
	if newStatus == "" {
		http.Error(w, "status requerido", http.StatusBadRequest)
		return
	}
	if newStatus != "new" && newStatus != "ack" && newStatus != "closed" {
		http.Error(w, "status inválido (use new, ack o closed)", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	var it SSHSuspiciousLogin
	err = s.db.QueryRow(ctx, `
        UPDATE ssh_suspicious_logins
        SET status = $1
        WHERE id = $2
        RETURNING
            id,
            created_at,
            hostname,
            username,
            remote_ip,
            failed_count_before_success,
            window_minutes,
            first_failed_at,
            success_at,
            status;
    `, newStatus, id).Scan(
		&it.ID,
		&it.CreatedAt,
		&it.Hostname,
		&it.Username,
		&it.RemoteIP,
		&it.FailedCountBeforeSuccess,
		&it.WindowMinutes,
		&it.FirstFailedAt,
		&it.SuccessAt,
		&it.Status,
	)
	if err != nil {
		log.Printf("Error actualizando ssh_suspicious_login id=%d: %v", id, err)
		http.Error(w, "ssh_suspicious_login no encontrado o error al actualizar", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(it); err != nil {
		log.Printf("Error serializando respuesta PATCH ssh_suspicious_login: %v", err)
	}
}

// ----------------------------------------------------
// SSH Timeline por IP (con dedupe)
// ----------------------------------------------------

func (s *Server) handleSSHTimeline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "solo GET", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	ip := q.Get("ip")
	username := q.Get("username")
	minStr := q.Get("minutes")
	limitStr := q.Get("limit")

	if ip == "" {
		http.Error(w, "ip requerida", http.StatusBadRequest)
		return
	}

	windowMinutes := 60
	if minStr != "" {
		if v, err := strconv.Atoi(minStr); err == nil && v > 0 && v <= 10080 {
			windowMinutes = v
		}
	}

	limit := 200
	if limitStr != "" {
		if v, err := strconv.Atoi(limitStr); err == nil && v > 0 && v <= 1000 {
			limit = v
		}
	}

	ctx := r.Context()
	now := time.Now().UTC()

	query := `
        SELECT DISTINCT
            e.ts,
            a.hostname,
            e.event_type,
            e.payload->>'username'  AS username,
            e.payload->>'remote_ip' AS remote_ip,
            COALESCE(e.payload->>'auth_method', '') AS auth_method,
            COALESCE(e.payload->>'is_root', '')      AS is_root_str,
            COALESCE(e.payload->>'dst_port', '')     AS dst_port_str,
            e.payload->>'raw_line'                   AS raw_line
        FROM raw_events e
        JOIN agents a ON e.agent_id = a.id
        WHERE e.source = 'auth'
          AND e.event_type IN ('ssh_failed_login', 'ssh_login_success')
          AND e.ts >= now() - ($1::int || ' minutes')::interval
          AND e.payload->>'remote_ip' = $2
    `
	args := []any{windowMinutes, ip}
	argPos := 3

	if username != "" {
		query += " AND e.payload->>'username' = $" + strconv.Itoa(argPos)
		args = append(args, username)
		argPos++
	}

	query += " ORDER BY e.ts ASC LIMIT $" + strconv.Itoa(argPos)
	args = append(args, limit)

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		log.Printf("Error consultando ssh_timeline: %v", err)
		http.Error(w, "error consultando timeline", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var events []SSHTimelineEvent
	for rows.Next() {
		var (
			ev         SSHTimelineEvent
			isRootStr  string
			dstPortStr string
		)
		if err := rows.Scan(
			&ev.Ts,
			&ev.Hostname,
			&ev.EventType,
			&ev.Username,
			&ev.RemoteIP,
			&ev.AuthMethod,
			&isRootStr,
			&dstPortStr,
			&ev.RawLine,
		); err != nil {
			log.Printf("Error escaneando ssh_timeline: %v", err)
			http.Error(w, "error leyendo timeline", http.StatusInternalServerError)
			return
		}

		ev.IsRoot = (isRootStr == "true")
		if dstPortStr != "" {
			if p, err := strconv.Atoi(dstPortStr); err == nil {
				ev.DstPort = p
			}
		}

		events = append(events, ev)
	}
	if rows.Err() != nil {
		log.Printf("Error final en rows ssh_timeline: %v", rows.Err())
		http.Error(w, "error leyendo timeline", http.StatusInternalServerError)
		return
	}

	if events == nil {
		events = []SSHTimelineEvent{}
	}

	resp := SSHTimelineResponse{
		IP:            ip,
		Username:      username,
		WindowMinutes: windowMinutes,
		Limit:         limit,
		GeneratedAt:   now,
		Events:        events,
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(resp); err != nil {
		log.Printf("Error serializando respuesta ssh_timeline: %v", err)
	}
}

// ----------------------------------------------------
// Sudo Timeline (con correlación SSH y dedupe)
// ----------------------------------------------------

func (s *Server) handleSudoTimeline(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "solo GET", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	sudoUser := q.Get("sudo_user")
	targetUser := q.Get("target_user")
	minStr := q.Get("minutes")
	limitStr := q.Get("limit")

	if sudoUser == "" && targetUser == "" {
		http.Error(w, "requiere al menos sudo_user o target_user", http.StatusBadRequest)
		return
	}

	windowMinutes := 60
	if minStr != "" {
		if v, err := strconv.Atoi(minStr); err == nil && v > 0 && v <= 10080 {
			windowMinutes = v
		}
	}

	limit := 200
	if limitStr != "" {
		if v, err := strconv.Atoi(limitStr); err == nil && v > 0 && v <= 1000 {
			limit = v
		}
	}

	ctx := r.Context()
	now := time.Now().UTC()

	query := `
        SELECT DISTINCT
            e.ts,
            a.hostname,
            e.payload->>'sudo_user'         AS sudo_user,
            e.payload->>'target_user'       AS target_user,
            COALESCE(e.payload->>'tty', '') AS tty,
            COALESCE(e.payload->>'pwd', '') AS pwd,
            COALESCE(e.payload->>'command', '') AS command,
            COALESCE(e.payload->>'is_sudo_root', '')   AS is_sudo_root_str,
            COALESCE(e.payload->>'is_target_root', '') AS is_target_root_str,
            e.payload->>'raw_line'          AS raw_line,
            COALESCE(se.remote_ip, '')      AS remote_ip
        FROM raw_events e
        JOIN agents a ON e.agent_id = a.id
        LEFT JOIN LATERAL (
            SELECT se.payload->>'remote_ip' AS remote_ip
            FROM raw_events se
            WHERE se.agent_id = e.agent_id
              AND se.source = 'auth'
              AND se.event_type = 'ssh_login_success'
              AND se.ts <= e.ts
              AND se.payload ? 'remote_ip'
            ORDER BY se.ts DESC
            LIMIT 1
        ) se ON TRUE
        WHERE e.source = 'auth'
          AND e.event_type = 'sudo_command'
          AND e.ts >= now() - ($1::int || ' minutes')::interval
    `
	args := []any{windowMinutes}
	argPos := 2

	if sudoUser != "" {
		query += " AND e.payload->>'sudo_user' = $" + strconv.Itoa(argPos)
		args = append(args, sudoUser)
		argPos++
	}
	if targetUser != "" {
		query += " AND e.payload->>'target_user' = $" + strconv.Itoa(argPos)
		args = append(args, targetUser)
		argPos++
	}

	query += " ORDER BY e.ts ASC LIMIT $" + strconv.Itoa(argPos)
	args = append(args, limit)

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		log.Printf("Error consultando sudo_timeline: %v", err)
		http.Error(w, "error consultando sudo_timeline", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var events []SudoTimelineEvent
	for rows.Next() {
		var ev SudoTimelineEvent
		var isSudoRootStr, isTargetRootStr string

		if err := rows.Scan(
			&ev.Ts,
			&ev.Hostname,
			&ev.SudoUser,
			&ev.TargetUser,
			&ev.TTY,
			&ev.Pwd,
			&ev.Command,
			&isSudoRootStr,
			&isTargetRootStr,
			&ev.RawLine,
			&ev.RemoteIP,
		); err != nil {
			log.Printf("Error escaneando sudo_timeline: %v", err)
			http.Error(w, "error leyendo sudo_timeline", http.StatusInternalServerError)
			return
		}

		ev.IsSudoRoot = (isSudoRootStr == "true")
		ev.IsTargetRoot = (isTargetRootStr == "true")

		events = append(events, ev)
	}
	if rows.Err() != nil {
		log.Printf("Error final en rows sudo_timeline: %v", rows.Err())
		http.Error(w, "error leyendo sudo_timeline", http.StatusInternalServerError)
		return
	}

	if events == nil {
		events = []SudoTimelineEvent{}
	}

	resp := SudoTimelineResponse{
		SudoUser:      sudoUser,
		TargetUser:    targetUser,
		WindowMinutes: windowMinutes,
		Limit:         limit,
		GeneratedAt:   now,
		Events:        events,
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(resp); err != nil {
		log.Printf("Error serializando respuesta sudo_timeline: %v", err)
	}
}

// ----------------------------------------------------
// API sudo_alerts (GET + PATCH)
// ----------------------------------------------------

func (s *Server) handleSudoAlerts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleSudoAlertsGET(w, r)
	case http.MethodPatch:
		s.handleSudoAlertsPATCH(w, r)
	default:
		http.Error(w, "solo GET o PATCH", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleSudoAlertsGET(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	status := q.Get("status")
	sudoUser := q.Get("sudo_user")
	targetUser := q.Get("target_user")
	ip := q.Get("ip")
	host := q.Get("hostname")
	minStr := q.Get("minutes")
	limitStr := q.Get("limit")

	windowMinutes := 60
	if minStr != "" {
		if v, err := strconv.Atoi(minStr); err == nil && v > 0 && v <= 10080 {
			windowMinutes = v
		}
	}

	limit := 50
	if limitStr != "" {
		if v, err := strconv.Atoi(limitStr); err == nil && v > 0 && v <= 500 {
			limit = v
		}
	}

	ctx := r.Context()
	now := time.Now().UTC()

	query := `
        SELECT
            id,
            created_at,
            hostname,
            sudo_user,
            target_user,
            remote_ip,
            tty,
            pwd,
            command,
            window_minutes,
            sudo_ts,
            status
        FROM sudo_alerts
        WHERE created_at >= now() - ($1::int || ' minutes')::interval
    `
	args := []any{windowMinutes}
	argPos := 2

	if status != "" {
		query += " AND status = $" + strconv.Itoa(argPos)
		args = append(args, status)
		argPos++
	}
	if sudoUser != "" {
		query += " AND sudo_user = $" + strconv.Itoa(argPos)
		args = append(args, sudoUser)
		argPos++
	}
	if targetUser != "" {
		query += " AND target_user = $" + strconv.Itoa(argPos)
		args = append(args, targetUser)
		argPos++
	}
	if ip != "" {
		query += " AND remote_ip = $" + strconv.Itoa(argPos)
		args = append(args, ip)
		argPos++
	}
	if host != "" {
		query += " AND hostname = $" + strconv.Itoa(argPos)
		args = append(args, host)
		argPos++
	}

	query += " ORDER BY created_at DESC LIMIT $" + strconv.Itoa(argPos)
	args = append(args, limit)

	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		log.Printf("Error consultando sudo_alerts: %v", err)
		http.Error(w, "error consultando sudo_alerts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var alerts []SudoAlert
	for rows.Next() {
		var a SudoAlert
		if err := rows.Scan(
			&a.ID,
			&a.CreatedAt,
			&a.Hostname,
			&a.SudoUser,
			&a.TargetUser,
			&a.RemoteIP,
			&a.TTY,
			&a.Pwd,
			&a.Command,
			&a.WindowMinutes,
			&a.SudoTs,
			&a.Status,
		); err != nil {
			log.Printf("Error escaneando sudo_alert: %v", err)
			http.Error(w, "error leyendo sudo_alerts", http.StatusInternalServerError)
			return
		}
		alerts = append(alerts, a)
	}
	if rows.Err() != nil {
		log.Printf("Error final en rows sudo_alerts: %v", rows.Err())
		http.Error(w, "error leyendo sudo_alerts", http.StatusInternalServerError)
		return
	}

	if alerts == nil {
		alerts = []SudoAlert{}
	}

	resp := SudoAlertsResponse{
		WindowMinutes: windowMinutes,
		Limit:         limit,
		GeneratedAt:   now,
		Alerts:        alerts,
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(resp); err != nil {
		log.Printf("Error serializando respuesta sudo_alerts: %v", err)
	}
}

func (s *Server) handleSudoAlertsPATCH(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	prefix := "/api/v1/sudo_alerts/"
	if !strings.HasPrefix(path, prefix) || len(path) <= len(prefix) {
		http.Error(w, "ruta inválida, use /api/v1/sudo_alerts/{id}", http.StatusBadRequest)
		return
	}
	idStr := strings.TrimPrefix(path, prefix)
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "id inválido", http.StatusBadRequest)
		return
	}

	var req SudoAlertUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "JSON inválido", http.StatusBadRequest)
		return
	}

	newStatus := strings.ToLower(strings.TrimSpace(req.Status))
	if newStatus == "" {
		http.Error(w, "status requerido", http.StatusBadRequest)
		return
	}
	if newStatus != "new" && newStatus != "ack" && newStatus != "closed" {
		http.Error(w, "status inválido (use new, ack o closed)", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	var a SudoAlert
	err = s.db.QueryRow(ctx, `
        UPDATE sudo_alerts
        SET status = $1
        WHERE id = $2
        RETURNING
            id,
            created_at,
            hostname,
            sudo_user,
            target_user,
            remote_ip,
            tty,
            pwd,
            command,
            window_minutes,
            sudo_ts,
            status;
    `, newStatus, id).Scan(
		&a.ID,
		&a.CreatedAt,
		&a.Hostname,
		&a.SudoUser,
		&a.TargetUser,
		&a.RemoteIP,
		&a.TTY,
		&a.Pwd,
		&a.Command,
		&a.WindowMinutes,
		&a.SudoTs,
		&a.Status,
	)
	if err != nil {
		log.Printf("Error actualizando sudo_alert id=%d: %v", id, err)
		http.Error(w, "sudo_alert no encontrada o error al actualizar", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(a); err != nil {
		log.Printf("Error serializando respuesta PATCH sudo_alert: %v", err)
	}
}
