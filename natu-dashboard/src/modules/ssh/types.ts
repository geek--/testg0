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

export interface SSHTimelineResponse {
  window_minutes: number;
  points?: SSHTimelinePoint[];
}
