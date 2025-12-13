<template>
  <div class="page">
    <div class="page-sticky">
      <header class="page-header">
        <h1 class="page-header__title">SSH · Resumen de actividad</h1>
        <p class="page-header__subtitle">
          Accesos recientes, intentos fallidos y distribución por IP/usuario para el servidor isov3.
        </p>
        <div class="tabs">
          <span class="tab tab-active">SSH (resumen)</span>
          <a href="/ssh/activity" class="tab">SSH (actividad)</a>
          <a href="/ssh/alerts" class="tab">Alertas SSH</a>
          <a href="/ssh/reactividad" class="tab">Reactividad</a>
          <a href="/ssh/sudo" class="tab">Sudo (resumen)</a>
          <a href="/ssh/sudo/activity" class="tab">Sudo (actividad)</a>
          <a href="/ssh/sudo-alerts" class="tab">Alertas sudo</a>
          <a href="/ssh/criticality" class="tab">Criticidad</a>
        </div>
      </header>

      <div class="activity-toolbar activity-toolbar--accent">
        <div class="activity-toolbar__group">
          <button class="btn-secondary" type="button" @click="refreshData(true)">
            Refrescar ahora
          </button>
          <span class="activity-toolbar__hint">Actualizado: {{ lastUpdatedLabel }}</span>
        </div>

        <div class="activity-toolbar__group activity-toolbar__group--compact">
          <label class="activity-toolbar__label">Auto-refresco</label>
          <select v-model.number="selectedInterval" class="activity-toolbar__input">
            <option v-for="opt in intervalOptions" :key="opt" :value="opt">
              Cada {{ opt }}s
            </option>
          </select>
          <label class="activity-toolbar__toggle">
            <input type="checkbox" v-model="autoRefreshEnabled" />
            <span>Activado</span>
          </label>
        </div>
      </div>
    </div>

    <!-- Estado: cargando resumen -->
    <section v-if="loadingSummary" class="section--loading">
      <LoadingSpinner /> Cargando resumen de SSH...
    </section>

    <!-- Estado: error resumen -->
    <section v-else-if="errorSummary" class="section--error">
      Error al cargar resumen de SSH: {{ errorSummary }}
    </section>

    <!-- Datos OK -->
    <section v-else class="page">
      <!-- Cards resumen -->
      <div class="stats-grid">
        <StatCard
          title="SSH failed (total)"
          :value="failedTotal"
          subtitle="Suma de intentos fallidos en todos los hosts"
        />

        <StatCard
          title="SSH success (total)"
          :value="successTotal"
          subtitle="Suma de logins exitosos en todos los hosts"
        />

        <StatCard
          title="Hosts monitoreados"
          :value="hostsCount"
          subtitle="Agentes activos reportando a natu-core"
        />
      </div>

      <!-- Top IPs / Top usuarios -->
      <div class="tables-grid" style="margin-top: 0.9rem;">
        <div class="table-card">
          <div class="table-card__title">Top IPs (failed)</div>
          <table class="table">
            <thead>
              <tr>
                <th>#</th>
                <th>IP</th>
                <th>Failed</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="(ip, idx) in topIps"
                :key="ip.remote_ip || ip.ip || idx"
                class="row--clickable"
                @click="openDetail('IP con intentos fallidos', ip, 'Top IPs (failed)')"
              >
                <td>{{ idx + 1 }}</td>
                <td>{{ ip.remote_ip || ip.ip || "-" }}</td>
                <td>{{ ip.failed ?? ip.failed_count ?? "-" }}</td>
              </tr>
              <tr v-if="topIps.length === 0">
                <td colspan="3" style="font-size: 0.78rem; color: #9ca3af;">
                  No se han registrado intentos fallidos aún.
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="table-card">
          <div class="table-card__title">Top usuarios</div>
          <table class="table">
            <thead>
              <tr>
                <th>#</th>
                <th>Usuario</th>
                <th>Failed</th>
                <th>Success</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="(u, idx) in topUsers"
                :key="u.username + '-' + idx"
                class="row--clickable"
                @click="openDetail('Top usuario SSH', u, 'Top usuarios (failed/success)')"
              >
                <td>{{ idx + 1 }}</td>
                <td>{{ u.username }}</td>
                <td>{{ u.failed ?? 0 }}</td>
                <td>{{ u.success ?? 0 }}</td>
              </tr>
              <tr v-if="topUsers.length === 0">
                <td colspan="4" style="font-size: 0.78rem; color: #9ca3af;">
                  No se han registrado usuarios todavía.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Timeline genérico (top IPs) -->
      <section style="margin-top: 1rem;">
        <div class="filters-bar filters-bar--compact">
          <div class="filters-bar__group">
            <label class="filters-bar__label">Buscar</label>
            <input
              v-model="filterTerm"
              class="filters-bar__input"
              type="text"
              placeholder="IP, host o usuario"
            />
          </div>
          <div class="filters-bar__actions">
            <span class="filters-bar__hint">Filtra el timeline SSH (host/IP/usuario)</span>
          </div>
        </div>

        <div class="table-card">
          <div class="table-card__title">Timeline SSH (top IPs) — últimos eventos</div>

          <!-- Estado timeline -->
          <div v-if="loadingTimeline" class="section--loading">
            <LoadingSpinner /> Cargando timeline SSH...
          </div>

          <div v-else-if="errorTimeline" class="section--error">
            Error al cargar timeline SSH: {{ errorTimeline }}
          </div>

          <template v-else>
            <table class="table">
              <thead>
                <tr>
                  <th>Fecha/Hora</th>
                  <th>Host</th>
                  <th>IP</th>
                  <th>Usuario</th>
                  <th>Tipo</th>
                  <th>Método</th>
                  <th>Descripción</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="(e, idx) in paginatedTimeline"
                  :key="idx"
                  class="row--clickable"
                  @click="openDetail('Evento SSH', e)"
                >
                  <td>{{ formatTs(e.ts || e.timestamp || e.time || "") }}</td>
                  <td>{{ e.hostname || e.host || "-" }}</td>
                  <td>{{ e._remote_ip || e.remote_ip || e.ip || "-" }}</td>
                  <td>{{ e.username || e.user || "-" }}</td>
                  <td>{{ humanEventType(e) }}</td>
                  <td>{{ e.auth_method || "-" }}</td>
                  <td>{{ shortDescription(e) }}</td>
                </tr>

                <tr v-if="topIps.length === 0">
                  <td colspan="7" style="font-size: 0.78rem; color: #9ca3af;">
                    No hay IPs con intentos fallidos registradas todavía.
                    El timeline genérico se construye a partir de las IPs más
                    activas en <strong>SSH failed</strong>. Para ver solo tus
                    logins exitosos necesitaremos extender el natu-core más
                    adelante.
                  </td>
                </tr>

                <tr
                  v-else-if="
                    topIps.length > 0 && filteredTimeline.length === 0
                  "
                >
                  <td colspan="7" style="font-size: 0.78rem; color: #9ca3af;">
                    No hay eventos SSH recientes para las IPs del Top en esta
                    ventana. Genera algunos intentos (fallidos o exitosos) para
                    ver actividad aquí.
                  </td>
                </tr>
              </tbody>
            </table>

            <div class="pagination" v-if="totalPages > 1">
              <button
                class="btn-secondary"
                type="button"
                :disabled="page === 1"
                @click="changePage(page - 1)"
              >
                Anterior
              </button>
              <span class="pagination__label">Página {{ page }} / {{ totalPages }}</span>
              <button
                class="btn-secondary"
                type="button"
                :disabled="page === totalPages"
                @click="changePage(page + 1)"
              >
                Siguiente
              </button>
            </div>
          </template>
        </div>
      </section>
    </section>

    <EventDetailDrawer
      v-model="showDetail"
      :title="detailTitle"
      :subtitle="detailSubtitle"
      :event="detailEvent"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { api } from "../../../services/api";
import StatCard from "../../../components/shared/StatCard.vue";
import LoadingSpinner from "../../../components/shared/LoadingSpinner.vue";
import EventDetailDrawer from "../../../components/shared/EventDetailDrawer.vue";

const MAX_TIMELINE_IPS = 5;

// estado resumen
const loadingSummary = ref(true);
const errorSummary = ref<string | null>(null);
const failedTotal = ref<number>(0);
const successTotal = ref<number>(0);
const hostsCount = ref<number>(0);
const topIps = ref<any[]>([]);
const topUsers = ref<any[]>([]);
const lastUpdated = ref<Date | null>(null);
const filterTerm = ref<string>("");
const page = ref<number>(1);
const pageSize = 10;
const intervalOptions = [3, 5, 15, 30, 60];
const selectedInterval = ref<number>(3);
const autoRefreshEnabled = ref<boolean>(true);
let refreshTimer: number | undefined;

// timeline agregado
const loadingTimeline = ref(false);
const errorTimeline = ref<string | null>(null);
const aggregatedTimelineEvents = ref<any[]>([]);
const filteredTimeline = computed(() => {
  if (!filterTerm.value) return aggregatedTimelineEvents.value;
  const term = filterTerm.value.toLowerCase();
  return aggregatedTimelineEvents.value.filter((e) => {
    return [
      e.hostname,
      e.host,
      e._remote_ip,
      e.remote_ip,
      e.ip,
      e.username,
      e.user,
    ]
      .filter(Boolean)
      .some((v: string) => String(v).toLowerCase().includes(term));
  });
});
const totalPages = computed(() =>
  Math.max(1, Math.ceil(filteredTimeline.value.length / pageSize)),
);
const paginatedTimeline = computed(() => {
  const start = (page.value - 1) * pageSize;
  return filteredTimeline.value.slice(start, start + pageSize);
});

// detalle
const showDetail = ref(false);
const detailEvent = ref<any | null>(null);
const detailTitle = ref("Detalle evento SSH");
const detailSubtitle = ref("Timeline SSH (top IPs)");

const lastUpdatedLabel = computed(() => {
  if (!lastUpdated.value) return "—";
  return lastUpdated.value.toLocaleTimeString();
});

function formatTs(ts: string): string {
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts || "—";
  return d.toLocaleString();
}

function humanEventType(e: any): string {
  const t = e.event_type || e.type || "";
  switch (t) {
    case "ssh_failed_login":
      return "Login fallido";
    case "ssh_login_success":
      return "Login exitoso";
    default:
      return t || "Evento SSH";
  }
}

function shortDescription(e: any): string {
  if (e.raw_line) {
    const s = String(e.raw_line);
    return s.length > 110 ? s.slice(0, 107) + "..." : s;
  }
  if (e.message || e.msg) return e.message || e.msg;
  return "Evento SSH registrado";
}

async function loadSummary() {
  loadingSummary.value = true;
  errorSummary.value = null;

  try {
    const res = await api.get<any>("/ssh_summary");

    const hosts = Array.isArray(res?.hosts) ? res.hosts : [];
    const hostsMap = new Map<string, any>();
    hosts.forEach((h: any) => {
      const key = String(h.hostname || h.host || h.agent_id || "host");
      const existing = hostsMap.get(key);
      if (!existing) {
        hostsMap.set(key, h);
        return;
      }

      existing.failed = Math.max(existing.failed ?? 0, h.failed ?? 0);
      existing.success = Math.max(existing.success ?? 0, h.success ?? 0);
    });

    const uniqueHosts = Array.from(hostsMap.values());
    hostsCount.value = uniqueHosts.length;

    failedTotal.value = uniqueHosts.reduce(
      (acc: number, h: any) => acc + (h.failed ?? 0),
      0,
    );
    successTotal.value = uniqueHosts.reduce(
      (acc: number, h: any) => acc + (h.success ?? 0),
      0,
    );

    const ips =
      res?.top_ips ??
      res?.ips ??
      res?.top_sources ??
      (Array.isArray(res) ? res : []);
    const ipMap = new Map<string, any>();
    (Array.isArray(ips) ? ips : []).forEach((item: any) => {
      const ip = item.remote_ip || item.ip;
      if (!ip) return;
      const failed = Number(item.failed ?? item.failures ?? 0) || 0;
      const success = Number(item.success ?? item.successes ?? 0) || 0;
      const prev = ipMap.get(ip);
      if (!prev) {
        ipMap.set(ip, {
          ...item,
          remote_ip: ip,
          failed,
          success,
        });
        return;
      }

      prev.failed = Math.max(prev.failed ?? 0, failed);
      prev.success = Math.max(prev.success ?? 0, success);
    });
    topIps.value = Array.from(ipMap.values());

    const users =
      res?.top_users ??
      res?.users ??
      res?.top_usernames ??
      (Array.isArray(res) ? res : []);
    const userMap = new Map<string, any>();
    (Array.isArray(users) ? users : []).forEach((item: any) => {
      const user = item.user || item.username;
      if (!user) return;
      const failed = Number(item.failed ?? item.failures ?? 0) || 0;
      const success = Number(item.success ?? item.successes ?? 0) || 0;
      const prev = userMap.get(user);
      if (!prev) {
        userMap.set(user, {
          ...item,
          username: user,
          failed,
          success,
        });
        return;
      }

      prev.failed = Math.max(prev.failed ?? 0, failed);
      prev.success = Math.max(prev.success ?? 0, success);
    });
    topUsers.value = Array.from(userMap.values());

    lastUpdated.value = new Date(res?.generated_at ?? Date.now());
  } catch (e: any) {
    errorSummary.value = e?.message ?? String(e);
  } finally {
    loadingSummary.value = false;
  }
}

async function loadAggregatedTimeline() {
  aggregatedTimelineEvents.value = [];

  if (!topIps.value.length) {
    return;
  }

  loadingTimeline.value = true;
  errorTimeline.value = null;

  try {
    const ips = topIps.value
      .map((r: any) => r.remote_ip || r.ip)
      .filter(Boolean)
      .slice(0, MAX_TIMELINE_IPS);

    const promises = ips.map((ip: string) =>
      api
        .get<any>("/ssh_timeline", {
          ip,
          limit: 200,
        })
        .then((res) => {
          const events =
            res?.events ??
            res?.items ??
            res?.points ??
            res?.data ??
            (Array.isArray(res) ? res : []);
          const arr = Array.isArray(events) ? events : [];
          return arr.map((e: any) => ({
            ...e,
            _remote_ip: ip,
          }));
        })
        .catch((err) => {
          console.error("Error cargando ssh_timeline para IP", ip, err);
          return [];
        }),
    );

    const all = await Promise.all(promises);
    const merged = all.flat();

    merged.sort((a, b) => {
      const ta = new Date(a.ts || a.timestamp || a.time || "").getTime();
      const tb = new Date(b.ts || b.timestamp || b.time || "").getTime();
      if (isNaN(ta) && isNaN(tb)) return 0;
      if (isNaN(ta)) return 1;
      if (isNaN(tb)) return -1;
      return tb - ta; // más reciente primero
    });

    const seen = new Set<string>();
    const unique: any[] = [];

    merged.forEach((evt) => {
      const ip = evt._remote_ip || evt.remote_ip || evt.ip || "";
      const ts = evt.ts || evt.timestamp || evt.time || "";
      const user = evt.user || evt.username || evt.ssh_user || "";
      const kind = evt.event_type || evt.type || "";
      const desc = evt.raw_line || evt.message || evt.msg || "";
      const key = `${ip}|${ts}|${user}|${kind}|${desc}`;
      if (seen.has(key)) return;
      seen.add(key);
      unique.push(evt);
    });

    aggregatedTimelineEvents.value = unique;
    page.value = 1;
  } catch (e: any) {
    errorTimeline.value = e?.message ?? String(e);
    aggregatedTimelineEvents.value = [];
  } finally {
    loadingTimeline.value = false;
  }
}

function clearAutoRefresh() {
  if (refreshTimer !== undefined) {
    window.clearInterval(refreshTimer);
    refreshTimer = undefined;
  }
}

function scheduleAutoRefresh() {
  clearAutoRefresh();
  if (!autoRefreshEnabled.value) return;

  refreshTimer = window.setInterval(() => {
    void refreshData(true);
  }, selectedInterval.value * 1000);
}

async function refreshData(refreshTimeline: boolean) {
  await loadSummary();
  if (refreshTimeline) {
    await loadAggregatedTimeline();
  }
}

function openDetail(title: string, evt: any, subtitle?: string) {
  detailTitle.value = title;
  detailSubtitle.value =
    subtitle ?? "Timeline SSH (top IPs agregadas)";
  detailEvent.value = evt;
  showDetail.value = true;
}

function changePage(next: number) {
  const maxPage = totalPages.value;
  if (next < 1 || next > maxPage) return;
  page.value = next;
}

onMounted(() => {
  void refreshData(true);
  scheduleAutoRefresh();
});

watch([autoRefreshEnabled, selectedInterval], () => {
  scheduleAutoRefresh();
});

watch(filterTerm, () => {
  page.value = 1;
});

watch([autoRefreshEnabled, selectedInterval], () => {
  scheduleAutoRefresh();
});

watch(filterTerm, () => {
  page.value = 1;
});

watch([autoRefreshEnabled, selectedInterval], () => {
  scheduleAutoRefresh();
});

watch(filterTerm, () => {
  page.value = 1;
});

watch([autoRefreshEnabled, selectedInterval], () => {
  scheduleAutoRefresh();
});
</script>

<style scoped>
.row--clickable {
  cursor: pointer;
}

.page-sticky {
  position: sticky;
  top: 0;
  z-index: 6;
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  padding-bottom: 0.35rem;
  margin-bottom: 0.6rem;
  background:
    linear-gradient(to bottom, rgba(2, 6, 23, 0.95), rgba(2, 6, 23, 0.9)),
    radial-gradient(circle at top left, rgba(59, 130, 246, 0.08), transparent 55%);
  box-shadow: 0 14px 30px rgba(2, 6, 23, 0.6);
}

/* Toolbar reutilizada de SSH (actividad) */
.activity-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  flex-wrap: wrap;
  padding: 0.65rem 0.85rem;
  border: 1px solid rgba(148, 163, 184, 0.25);
  border-radius: 0.9rem;
  background: linear-gradient(180deg, rgba(15, 23, 42, 0.92), rgba(15, 23, 42, 0.82));
  box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.05);
}

.activity-toolbar--padded {
  padding: 0.65rem 0.8rem;
  background: linear-gradient(90deg, rgba(30, 41, 59, 0.75), rgba(15, 23, 42, 0.82));
  border-color: rgba(148, 163, 184, 0.32);
}

.activity-toolbar--accent {
  padding: 0.55rem 0.8rem;
  background:
    radial-gradient(circle at 20% 20%, rgba(59, 130, 246, 0.16), transparent 45%),
    linear-gradient(90deg, rgba(15, 23, 42, 0.95), rgba(11, 17, 29, 0.88));
  border-color: rgba(148, 163, 184, 0.35);
}

.activity-toolbar--accent {
  padding: 0.55rem 0.8rem;
  background:
    radial-gradient(circle at 20% 20%, rgba(59, 130, 246, 0.16), transparent 45%),
    linear-gradient(90deg, rgba(15, 23, 42, 0.95), rgba(11, 17, 29, 0.88));
  border-color: rgba(148, 163, 184, 0.35);
}

.activity-toolbar--accent {
  padding: 0.55rem 0.8rem;
  background:
    radial-gradient(circle at 20% 20%, rgba(59, 130, 246, 0.16), transparent 45%),
    linear-gradient(90deg, rgba(15, 23, 42, 0.95), rgba(11, 17, 29, 0.88));
  border-color: rgba(148, 163, 184, 0.35);
}

.activity-toolbar--accent {
  padding: 0.55rem 0.8rem;
  background:
    radial-gradient(circle at 20% 20%, rgba(59, 130, 246, 0.16), transparent 45%),
    linear-gradient(90deg, rgba(15, 23, 42, 0.95), rgba(11, 17, 29, 0.88));
  border-color: rgba(148, 163, 184, 0.35);
}

.activity-toolbar__group {
  display: flex;
  align-items: center;
  gap: 0.6rem;
  flex-wrap: wrap;
}

.activity-toolbar__group--compact {
  gap: 0.45rem;
}

.activity-toolbar__label {
  font-size: 0.82rem;
  color: #cbd5e1;
}

.activity-toolbar__input {
  background: rgba(17, 24, 39, 0.85);
  border: 1px solid rgba(148, 163, 184, 0.35);
  border-radius: 0.55rem;
  padding: 0.38rem 0.6rem;
  color: #e2e8f0;
  min-width: 96px;
}

.activity-toolbar__hint {
  font-size: 0.78rem;
  color: #94a3b8;
}

.activity-toolbar__toggle {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  font-size: 0.9rem;
  color: #e2e8f0;
  padding: 0.2rem 0.4rem;
  border-radius: 0.45rem;
  background: rgba(59, 130, 246, 0.12);
}

.filters-bar {
  display: flex;
  gap: 1rem;
  align-items: flex-end;
  padding: 0.65rem 0.85rem;
  border-radius: 0.75rem;
  border: 1px solid rgba(148, 163, 184, 0.16);
  background: radial-gradient(
      circle at top left,
      rgba(56, 189, 248, 0.08),
      transparent
    ),
    rgba(15, 23, 42, 0.9);
}

.filters-bar--compact {
  margin-bottom: 0.65rem;
}

.filters-bar__group {
  display: flex;
  flex-direction: column;
  min-width: 180px;
}

.filters-bar__label {
  font-size: 0.75rem;
  color: #9ca3af;
  margin-bottom: 0.25rem;
}

.filters-bar__input {
  background: rgba(15, 23, 42, 0.9);
  border-radius: 0.5rem;
  border: 1px solid rgba(148, 163, 184, 0.5);
  padding: 0.35rem 0.6rem;
  font-size: 0.85rem;
  color: #e5e7eb;
}

.filters-bar__input::placeholder {
  color: #6b7280;
}

.filters-bar__actions {
  margin-left: auto;
}

.filters-bar__hint {
  font-size: 0.72rem;
  color: #9ca3af;
}

.filters-bar {
  display: flex;
  gap: 1rem;
  align-items: flex-end;
  padding: 0.65rem 0.85rem;
  border-radius: 0.75rem;
  border: 1px solid rgba(148, 163, 184, 0.16);
  background: radial-gradient(
      circle at top left,
      rgba(56, 189, 248, 0.08),
      transparent
    ),
    rgba(15, 23, 42, 0.9);
}

.filters-bar--compact {
  margin-bottom: 0.65rem;
}

.filters-bar__group {
  display: flex;
  flex-direction: column;
  min-width: 180px;
}

.filters-bar__label {
  font-size: 0.75rem;
  color: #9ca3af;
  margin-bottom: 0.25rem;
}

.filters-bar__input {
  background: rgba(15, 23, 42, 0.9);
  border-radius: 0.5rem;
  border: 1px solid rgba(148, 163, 184, 0.5);
  padding: 0.35rem 0.6rem;
  font-size: 0.85rem;
  color: #e5e7eb;
}

.filters-bar__input::placeholder {
  color: #6b7280;
}

.filters-bar__actions {
  margin-left: auto;
}

.filters-bar__hint {
  font-size: 0.72rem;
  color: #9ca3af;
}

.filters-bar {
  display: flex;
  gap: 1rem;
  align-items: flex-end;
  padding: 0.65rem 0.85rem;
  border-radius: 0.75rem;
  border: 1px solid rgba(148, 163, 184, 0.16);
  background: radial-gradient(
      circle at top left,
      rgba(56, 189, 248, 0.08),
      transparent
    ),
    rgba(15, 23, 42, 0.9);
}

.filters-bar--compact {
  margin-bottom: 0.65rem;
}

.filters-bar__group {
  display: flex;
  flex-direction: column;
  min-width: 180px;
}

.filters-bar__label {
  font-size: 0.75rem;
  color: #9ca3af;
  margin-bottom: 0.25rem;
}

.filters-bar__input {
  background: rgba(15, 23, 42, 0.9);
  border-radius: 0.5rem;
  border: 1px solid rgba(148, 163, 184, 0.5);
  padding: 0.35rem 0.6rem;
  font-size: 0.85rem;
  color: #e5e7eb;
}

.filters-bar__input::placeholder {
  color: #6b7280;
}

.filters-bar__actions {
  margin-left: auto;
}

.filters-bar__hint {
  font-size: 0.72rem;
  color: #9ca3af;
}

.btn-secondary {
  border-radius: 9999px;
  border: 1px solid rgba(148, 163, 184, 0.35);
  background: rgba(15, 23, 42, 0.9);
  padding: 0.3rem 0.75rem;
  font-size: 0.8rem;
  color: #e5e7eb;
  cursor: pointer;
}

.btn-secondary--active {
  background: linear-gradient(90deg, #2563eb, #4f46e5);
  border-color: transparent;
}

.pagination {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  margin-top: 0.75rem;
}

.pagination__label {
  font-size: 0.82rem;
  color: #94a3b8;
}
</style>
