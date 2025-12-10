package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

type SSHActivityIP struct {
	RemoteIP string    `json:"remote_ip"`
	Failed   int       `json:"failed"`
	Success  int       `json:"success"`
	LastSeen time.Time `json:"last_seen"`
}

type SSHActivityResponse struct {
	WindowMinutes int                `json:"window_minutes"`
	GeneratedAt   time.Time          `json:"generated_at"`
	IPs           []SSHActivityIP    `json:"ips"`
	Events        []SSHTimelineEvent `json:"events"`
}

func (s *Server) handleSSHActivity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "solo GET", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	minStr := q.Get("minutes")
	limitStr := q.Get("limit")

	windowMinutes := 240
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

	rows, err := s.db.Query(ctx, `
        SELECT
            e.payload->>'remote_ip' AS remote_ip,
            COUNT(*) FILTER (WHERE e.event_type = 'ssh_failed_login')  AS failed_count,
            COUNT(*) FILTER (WHERE e.event_type = 'ssh_login_success') AS success_count,
            MAX(e.ts) AS last_seen
        FROM raw_events e
        WHERE e.source = 'auth'
          AND e.event_type IN ('ssh_failed_login', 'ssh_login_success')
          AND e.ts >= now() - ($1::int || ' minutes')::interval
          AND e.payload ? 'remote_ip'
        GROUP BY remote_ip
        ORDER BY last_seen DESC;
    `, windowMinutes)
	if err != nil {
		http.Error(w, "error consultando IPs de SSH", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var ips []SSHActivityIP
	for rows.Next() {
		var item SSHActivityIP
		if err := rows.Scan(&item.RemoteIP, &item.Failed, &item.Success, &item.LastSeen); err != nil {
			http.Error(w, "error leyendo IPs SSH", http.StatusInternalServerError)
			return
		}
		ips = append(ips, item)
	}
	if rows.Err() != nil {
		http.Error(w, "error final leyendo IPs SSH", http.StatusInternalServerError)
		return
	}

	if ips == nil {
		ips = []SSHActivityIP{}
	}

	evtRows, err := s.db.Query(ctx, `
        SELECT
            e.ts,
            a.hostname,
            e.event_type,
            COALESCE(e.payload->>'username', '')   AS username,
            COALESCE(e.payload->>'remote_ip', '')  AS remote_ip,
            COALESCE(e.payload->>'auth_method', '') AS auth_method,
            COALESCE((e.payload->>'dst_port')::int, 0) AS dst_port,
            COALESCE((e.payload->>'is_root')::bool, false) AS is_root,
            COALESCE(e.payload->>'raw_line', '') AS raw_line
        FROM raw_events e
        JOIN agents a ON e.agent_id = a.id
        WHERE e.source = 'auth'
          AND e.event_type IN ('ssh_failed_login', 'ssh_login_success')
          AND e.ts >= now() - ($1::int || ' minutes')::interval
        ORDER BY e.ts DESC
        LIMIT $2;
    `, windowMinutes, limit)
	if err != nil {
		http.Error(w, "error consultando actividad SSH", http.StatusInternalServerError)
		return
	}
	defer evtRows.Close()

	var events []SSHTimelineEvent
	for evtRows.Next() {
		var evt SSHTimelineEvent
		if err := evtRows.Scan(&evt.Ts, &evt.Hostname, &evt.EventType, &evt.Username, &evt.RemoteIP, &evt.AuthMethod, &evt.DstPort, &evt.IsRoot, &evt.RawLine); err != nil {
			http.Error(w, "error leyendo actividad SSH", http.StatusInternalServerError)
			return
		}
		events = append(events, evt)
	}
	if evtRows.Err() != nil {
		http.Error(w, "error final leyendo actividad SSH", http.StatusInternalServerError)
		return
	}

	if events == nil {
		events = []SSHTimelineEvent{}
	}

	resp := SSHActivityResponse{
		WindowMinutes: windowMinutes,
		GeneratedAt:   now,
		IPs:           ips,
		Events:        events,
	}

	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(resp); err != nil {
		http.Error(w, "error serializando respuesta", http.StatusInternalServerError)
		return
	}
}
