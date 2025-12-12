// src/modules/ssh/types.ts

// Summary SSH

export interface SSHHostSummary {
  hostname: string;
  failed: number;
  success: number;
}

export interface SSHTopIP {
  remote_ip: string;
  failed: number;
}

export interface SSHTopUser {
  username: string;
  failed: number;
  success?: number;
}

export interface SSHSummaryResponse {
  window_minutes: number;
  generated_at: string;
  hosts?: SSHHostSummary[];
  top_ips?: SSHTopIP[];
  top_users?: SSHTopUser[];
}

// Timeline SSH

export interface SSHTimelinePoint {
  ts: string;
  failed: number;
  success: number;
}

export interface SSHTimelineEvent {
  ts: string;
  hostname: string;
  event_type: string;
  username: string;
  remote_ip: string;
  auth_method?: string;
  dst_port?: number;
  is_root?: boolean;
  raw_line?: string;
}

export interface SSHTimelineResponse {
  window_minutes: number;
  points?: SSHTimelinePoint[];
}

// SSH Activity

export interface SSHActivityIP {
  remote_ip: string;
  failed: number;
  success: number;
  last_seen: string;
}

export interface SSHActivityEvent {
  ts: string;
  hostname: string;
  event_type: string;
  username: string;
  remote_ip: string;
  auth_method?: string;
  dst_port?: number;
  is_root?: boolean;
  raw_line?: string;
}

export interface SSHActivityResponse {
  window_minutes: number;
  generated_at: string;
  ips: SSHActivityIP[];
  events: SSHActivityEvent[];
}

// SSH bans / reactividad
export interface SSHBanItem {
  hostname: string;
  ip: string;
  jail: string;
  banned_at?: string;
  reason?: string;
  source?: string;
  synced_at: string;
}

export interface SSHBanResponse {
  window_minutes: number;
  generated_at: string;
  bans: SSHBanItem[];
}
