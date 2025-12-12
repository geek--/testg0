<template>
  <div class="page">
    <header class="page-header">
      <h1 class="page-header__title">SSH · Actividad</h1>
      <p class="page-header__subtitle">
        Lista de IPs con actividad SSH reciente, feed en vivo y timeline por IP sin
        escribir filtros manualmente.
      </p>
      <div class="tabs">
        <a href="/ssh" class="tab">SSH (resumen)</a>
        <span class="tab tab-active">SSH (actividad)</span>
        <a href="/ssh/alerts" class="tab">Alertas SSH</a>
        <a href="/ssh/reactividad" class="tab">Reactividad</a>
        <a href="/ssh/sudo" class="tab">Sudo (resumen)</a>
        <a href="/ssh/sudo/activity" class="tab">Sudo (actividad)</a>
        <a href="/ssh/sudo-alerts" class="tab">Alertas sudo</a>
        <a href="/ssh/criticality" class="tab">Criticidad</a>
      </div>
    </header>

    <section class="page" style="gap: 0.75rem; display: flex; flex-direction: column;">
      <div class="activity-toolbar">
        <div class="activity-toolbar__group">
          <label class="activity-toolbar__label">Ventana (min)</label>
          <input
            v-model.number="windowMinutes"
            class="activity-toolbar__input"
            type="number"
            min="5"
            max="10080"
          />
          <button class="btn-secondary" type="button" @click="refreshData(true)">
            Refrescar ahora
          </button>
          <span class="activity-toolbar__hint">Actualizado: {{ lastUpdatedLabel }}</span>
        </div>

        <div class="activity-toolbar__group">
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

      <div class="tables-grid">
        <div class="table-card">
          <div class="table-card__title">IPs con actividad SSH</div>

          <div v-if="loadingActivity" class="section--loading">
            <LoadingSpinner /> Cargando actividad SSH...
          </div>
          <div v-else-if="errorActivity" class="section--error">
            {{ errorActivity }}
          </div>
          <template v-else>
            <table class="table">
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Failed</th>
                  <th>Success</th>
                  <th>Última vez</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="ip in ips" :key="ip.remote_ip">
                  <td>{{ ip.remote_ip }}</td>
                  <td>{{ ip.failed }}</td>
                  <td>{{ ip.success }}</td>
                  <td>{{ formatTs(ip.last_seen) }}</td>
                  <td>
                    <button
                      class="btn-secondary"
                      :class="{ 'btn-secondary--active': selectedIp === ip.remote_ip }"
                      type="button"
                      @click="selectIp(ip.remote_ip)"
                    >
                      Ver timeline
                    </button>
                  </td>
                </tr>
                <tr v-if="ips.length === 0">
                  <td colspan="5" style="font-size: 0.78rem; color: #9ca3af;">
                    No hay IPs con actividad SSH en la ventana seleccionada.
                  </td>
                </tr>
              </tbody>
            </table>
          </template>
        </div>

        <div class="table-card">
          <div class="table-card__title">
            Timeline de IP
            <span v-if="selectedIp" class="pill">{{ selectedIp }}</span>
            <span v-else class="pill pill--muted">Selecciona una IP</span>
          </div>

          <div v-if="loadingTimeline" class="section--loading">
            <LoadingSpinner /> Cargando timeline...
          </div>
          <div v-else-if="errorTimeline" class="section--error">
            {{ errorTimeline }}
          </div>
          <template v-else>
            <table class="table">
              <thead>
                <tr>
                  <th>Fecha/Hora</th>
                  <th>Host</th>
                  <th>Usuario</th>
                  <th>Tipo</th>
                  <th>Método</th>
                  <th>Raw</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="(evt, idx) in timelineEvents" :key="idx">
                  <td>{{ formatTs(evt.ts) }}</td>
                  <td>{{ evt.hostname || '-' }}</td>
                  <td>{{ evt.username || '-' }}</td>
                  <td>{{ humanEventType(evt.event_type) }}</td>
                  <td>{{ evt.auth_method || '-' }}</td>
                  <td>{{ shortDescription(evt.raw_line) }}</td>
                </tr>
                <tr v-if="selectedIp && timelineEvents.length === 0">
                  <td colspan="6" style="font-size: 0.78rem; color: #9ca3af;">
                    No hay eventos recientes para esta IP en la ventana indicada.
                  </td>
                </tr>
                <tr v-if="!selectedIp">
                  <td colspan="6" style="font-size: 0.78rem; color: #9ca3af;">
                    Selecciona una IP para ver su timeline.
                  </td>
                </tr>
              </tbody>
            </table>
          </template>
        </div>
      </div>

      <div class="table-card">
        <div class="table-card__title">SSH · Live feed</div>
        <div v-if="loadingActivity" class="section--loading">
          <LoadingSpinner /> Cargando feed...
        </div>
        <div v-else-if="errorActivity" class="section--error">{{ errorActivity }}</div>
        <table v-else class="table">
          <thead>
            <tr>
              <th>Fecha/Hora</th>
              <th>Host</th>
              <th>IP</th>
              <th>Usuario</th>
              <th>Tipo</th>
              <th>Descripción</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="(evt, idx) in liveFeed" :key="idx">
              <td>{{ formatTs(evt.ts) }}</td>
              <td>{{ evt.hostname || '-' }}</td>
              <td>{{ evt.remote_ip || '-' }}</td>
              <td>{{ evt.username || '-' }}</td>
              <td>{{ humanEventType(evt.event_type) }}</td>
              <td>{{ shortDescription(evt.raw_line) }}</td>
            </tr>
            <tr v-if="liveFeed.length === 0">
              <td colspan="6" style="font-size: 0.78rem; color: #9ca3af;">
                Aún no hay eventos recientes para mostrar.
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import LoadingSpinner from "../../../components/shared/LoadingSpinner.vue";
import { api } from "../../../services/api";
import type {
  SSHActivityEvent,
  SSHActivityIP,
  SSHActivityResponse,
  SSHTimelineEvent,
} from "../types";

const windowMinutes = ref<number>(240);
const ips = ref<SSHActivityIP[]>([]);
const liveFeed = ref<SSHActivityEvent[]>([]);
const loadingActivity = ref<boolean>(true);
const errorActivity = ref<string | null>(null);
const lastUpdated = ref<Date | null>(null);

const selectedIp = ref<string | null>(null);
const timelineEvents = ref<SSHTimelineEvent[]>([]);
const loadingTimeline = ref<boolean>(false);
const errorTimeline = ref<string | null>(null);

const intervalOptions = [5, 10, 30, 60];
const selectedInterval = ref<number>(30);
const autoRefreshEnabled = ref<boolean>(true);
let refreshHandle: number | null = null;

const lastUpdatedLabel = computed(() => {
  if (!lastUpdated.value) return "—";
  return lastUpdated.value.toLocaleTimeString();
});

function formatTs(ts: string): string {
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts || "—";
  return d.toLocaleString();
}

function humanEventType(type: string): string {
  switch (type) {
    case "ssh_failed_login":
      return "Login fallido";
    case "ssh_login_success":
      return "Login exitoso";
    default:
      return type || "Evento";
  }
}

function shortDescription(raw?: string): string {
  if (!raw) return "Evento SSH";
  return raw.length > 90 ? `${raw.slice(0, 87)}...` : raw;
}

async function loadActivity() {
  loadingActivity.value = true;
  errorActivity.value = null;

  try {
    const res = await api.get<SSHActivityResponse>("/ssh_activity", {
      minutes: windowMinutes.value,
      limit: 100,
    });

    ips.value = Array.isArray(res?.ips) ? res.ips : [];
    liveFeed.value = Array.isArray(res?.events) ? res.events : [];
    lastUpdated.value = new Date(res?.generated_at ?? Date.now());

    if (!selectedIp.value && ips.value.length > 0) {
      selectedIp.value = ips.value[0]?.remote_ip ?? null;
    } else if (
      selectedIp.value &&
      !ips.value.some((ip) => ip.remote_ip === selectedIp.value)
    ) {
      selectedIp.value = ips.value[0]?.remote_ip ?? null;
    }
  } catch (e: any) {
    errorActivity.value = e?.message ?? String(e);
    ips.value = [];
    liveFeed.value = [];
  } finally {
    loadingActivity.value = false;
  }
}

async function loadTimeline(ip: string | null) {
  if (!ip) {
    timelineEvents.value = [];
    return;
  }

  loadingTimeline.value = true;
  errorTimeline.value = null;

  try {
    const res = await api.get<any>("/ssh_timeline", {
      ip,
      minutes: windowMinutes.value,
      limit: 200,
    });
    const events = Array.isArray(res?.events) ? res.events : [];
    timelineEvents.value = events;
  } catch (e: any) {
    errorTimeline.value = e?.message ?? String(e);
    timelineEvents.value = [];
  } finally {
    loadingTimeline.value = false;
  }
}

function selectIp(ip: string) {
  if (selectedIp.value === ip) return;
  selectedIp.value = ip;
}

async function refreshData(refreshTimeline: boolean) {
  await loadActivity();
  if (refreshTimeline) {
    await loadTimeline(selectedIp.value);
  }
}

function clearAutoRefresh() {
  if (refreshHandle) {
    window.clearInterval(refreshHandle);
    refreshHandle = null;
  }
}

function setupAutoRefresh() {
  clearAutoRefresh();
  if (!autoRefreshEnabled.value) return;

  refreshHandle = window.setInterval(() => {
    void refreshData(true);
  }, selectedInterval.value * 1000);
}

watch(selectedIp, (ip) => {
  void loadTimeline(ip);
});

watch([selectedInterval, autoRefreshEnabled], () => {
  setupAutoRefresh();
});

onMounted(() => {
  void refreshData(true);
  setupAutoRefresh();
});

onBeforeUnmount(() => {
  clearAutoRefresh();
});
</script>

<style scoped>
.activity-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  flex-wrap: wrap;
  padding: 0.45rem 0.6rem;
  border: 1px solid rgba(148, 163, 184, 0.25);
  border-radius: 0.75rem;
  background: rgba(15, 23, 42, 0.6);
}

.activity-toolbar__group {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.activity-toolbar__label {
  font-size: 0.82rem;
  color: #cbd5e1;
}

.activity-toolbar__input {
  background: rgba(15, 23, 42, 0.9);
  border: 1px solid rgba(148, 163, 184, 0.3);
  border-radius: 0.5rem;
  padding: 0.3rem 0.5rem;
  color: #e2e8f0;
  min-width: 90px;
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

.pill {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  padding: 0.2rem 0.55rem;
  border-radius: 9999px;
  background: rgba(59, 130, 246, 0.12);
  color: #bfdbfe;
  font-size: 0.75rem;
}

.pill--muted {
  background: rgba(148, 163, 184, 0.15);
  color: #e2e8f0;
}
</style>
