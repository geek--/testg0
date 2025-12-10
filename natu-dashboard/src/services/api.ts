// src/services/api.ts

const API_BASE = "/api/v1";

async function apiGet<T>(
  path: string,
  params?: Record<string, any>,
): Promise<T> {
  // path será algo como "/ssh_summary" o "/ssh_timeline"
  const url = new URL(API_BASE + path, window.location.origin);

  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== null) {
        url.searchParams.append(key, String(value));
      }
    }
  }

  const res = await fetch(url.toString(), {
    method: "GET",
    headers: {
      Accept: "application/json",
    },
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(
      `API ${url.pathname} ${res.status} ${res.statusText} - ${text}`,
    );
  }

  return (await res.json()) as T;
}

export const api = {
  get: apiGet,
};
