<template>
  <div class="page">
    <header class="page-header">
      <h1 class="page-header__title">SSH · Alertas & logins sospechosos</h1>
      <p class="page-header__subtitle">
        Vista detallada de alertas generadas por el módulo SSH y logins marcados como sospechosos
        en el servidor isov3.
      </p>
      <div class="tabs">
        <a href="/ssh" class="tab">SSH (resumen)</a>
        <a href="/ssh/activity" class="tab">SSH (actividad)</a>
        <span class="tab tab-active">Alertas SSH</span>
        <a href="/ssh/sudo" class="tab">Sudo (actividad)</a>
        <a href="/ssh/sudo-alerts" class="tab">Alertas sudo</a>
      </div>
    </header>

    <section class="page">
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
          <button class="btn-secondary" type="button" @click="refreshData()">
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

      <section v-if="loadingAlerts || loadingSuspicious" class="section--loading">
        <LoadingSpinner /> Cargando alertas y logins sospechosos...
      </section>

      <section v-else-if="error" class="section--error">
        {{ error }}
      </section>

      <template v-else>
        <div class="stats-grid">
          <StatCard
            title="Ventana analizada"
            :value="(windowMinutes ?? WINDOW_MINUTES) + ' min'"
            subtitle="Parámetro minutes en /api/v1/ssh_alerts y /api/v1/ssh_suspicious_logins"
          />

          <StatCard
            title="Alertas SSH"
            :value="alerts.length"
            subtitle="Número de alertas generadas en la ventana seleccionada"
          />

          <StatCard
            title="Logins sospechosos"
            :value="suspiciousLogins.length"
            subtitle="Intentos de acceso catalogados como sospechosos"
          />

          <StatCard
            title="Última alerta"
            :value="lastAlertTsDisplay"
            subtitle="Marca de tiempo de la alerta más reciente (si existe)"
          />
        </div>

        <div class="tables-grid" style="margin-top: 0.8rem;">
          <!-- Alertas SSH -->
          <div class="table-card">
            <div class="table-card__title">Alertas SSH recientes</div>

            <table class="table">
              <thead>
                <tr>
                  <th>Fecha/Hora</th>
                  <th>Host</th>
                  <th>IP</th>
                  <th>Usuario</th>
                  <th>Regla</th>
                  <th>Severidad</th>
                  <th>Mensaje</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="(a, idx) in alerts"
                  :key="idx"
                  class="row--clickable"
                  @click="openDetail('Alerta SSH', a)"
                >
                  <td>{{ formatAlertTs(a) }}</td>
                  <td>{{ a.hostname || a.host || "-" }}</td>
                  <td>{{ a.remote_ip || a.ip || a.source_ip || "-" }}</td>
                  <td>{{ a.username || a.user || "-" }}</td>
                  <td>{{ a.rule || a.type || "-" }}</td>
                  <td>{{ a.severity || a.level || "-" }}</td>
                  <td>{{ a.message || a.msg || a.description || "-" }}</td>
                </tr>
                <tr v-if="alerts.length === 0">
                  <td colspan="7" style="font-size: 0.78rem; color: #9ca3af;">
                    No se han registrado alertas SSH en la ventana seleccionada.
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <!-- Logins sospechosos -->
          <div class="table-card">
            <div class="table-card__title">Logins sospechosos (SSH)</div>

            <table class="table">
              <thead>
                <tr>
                  <th>Fecha/Hora</th>
                  <th>Host</th>
                  <th>IP</th>
                  <th>Usuario</th>
                  <th v-if="hasFailedBeforeColumn">Failed antes</th>
                  <th v-if="hasReasonColumn">Razón</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="(s, idx) in suspiciousLogins"
                  :key="idx"
                  class="row--clickable"
                  @click="openDetail('Login sospechoso SSH', s)"
                >
                  <td>{{ formatSuspiciousTs(s) }}</td>
                  <td>{{ s.hostname || s.host || "-" }}</td>
                  <td>{{ s.remote_ip || s.ip || s.source_ip || "-" }}</td>
                  <td>{{ s.username || s.user || "-" }}</td>
                  <td v-if="hasFailedBeforeColumn">
                    {{ resolveFailedBefore(s) ?? "N/A" }}
                  </td>
                  <td v-if="hasReasonColumn">
                    {{ resolveReason(s) ?? "N/A" }}
                  </td>
                </tr>
                <tr v-if="suspiciousLogins.length === 0">
                  <td
                    :colspan="4 + (hasFailedBeforeColumn ? 1 : 0) + (hasReasonColumn ? 1 : 0)"
                    style="font-size: 0.78rem; color: #9ca3af;"
                  >
                    No hay logins marcados como sospechosos en la ventana seleccionada.
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </template>
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
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { api } from "../../../services/api";
import StatCard from "../../../components/shared/StatCard.vue";
import LoadingSpinner from "../../../components/shared/LoadingSpinner.vue";
import EventDetailDrawer from "../../../components/shared/EventDetailDrawer.vue";

const error = ref<string | null>(null);

const alerts = ref<any[]>([]);
const suspiciousLogins = ref<any[]>([]);
const windowMinutes = ref<number>(240);

const loadingAlerts = ref(true);
const loadingSuspicious = ref(true);

// detalle
const showDetail = ref(false);
const detailEvent = ref<any | null>(null);
const detailTitle = ref("Detalle");
const detailSubtitle = ref("");

const WINDOW_MINUTES = 240;
const intervalOptions = [5, 10, 30, 60];
const selectedInterval = ref<number>(30);
const autoRefreshEnabled = ref<boolean>(true);
let refreshHandle: number | null = null;
const lastUpdated = ref<Date | null>(null);

// ---- helpers para columnas dinámicas ----
function resolveFailedBefore(s: any): number | null {
  if (typeof s?.failed_before === "number") return s.failed_before;
  if (typeof s?.failed_before_count === "number")
    return s.failed_before_count;
  if (typeof s?.failed_count === "number") return s.failed_count;
  if (typeof s?.previous_failures === "number")
    return s.previous_failures;
  if (typeof s?.pre_failures === "number") return s.pre_failures;
  if (s?.meta && typeof s.meta.failed_before === "number")
    return s.meta.failed_before;
  return null;
}

function resolveReason(s: any): string | null {
  const val =
    s?.reason ||
    s?.message ||
    s?.msg ||
    s?.classification ||
    s?.classifier ||
    s?.kind ||
    (s?.meta && (s.meta.reason || s.meta.message));

  if (val && String(val).trim() !== "") return String(val);
  return null;
}

const hasFailedBeforeColumn = computed(() =>
  suspiciousLogins.value.some((s) => resolveFailedBefore(s) !== null),
);

const hasReasonColumn = computed(() =>
  suspiciousLogins.value.some((s) => resolveReason(s) !== null),
);

const lastUpdatedLabel = computed(() => {
  if (!lastUpdated.value) return "—";
  return lastUpdated.value.toLocaleTimeString();
});

// ---- últimos tiempos / formato ----
const lastAlertTsDisplay = computed(() => {
  if (!alerts.value.length) return "—";
  const last = alerts.value.reduce((latest, current) => {
    const tCurrent = new Date(extractTs(current)).getTime();
    const tLatest = new Date(extractTs(latest)).getTime();
    return tCurrent > tLatest ? current : latest;
  }, alerts.value[0]);
  return formatTs(extractTs(last));
});

function extractTs(obj: any): string {
  return (
    obj?.ts ||
    obj?.timestamp ||
    obj?.time ||
    obj?.created_at ||
    obj?.detected_at ||
    obj?.when ||
    ""
  );
}

function formatTs(ts: string): string {
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts || "—";
  return d.toLocaleString();
}

function formatAlertTs(a: any): string {
  return formatTs(extractTs(a));
}

function formatSuspiciousTs(s: any): string {
  return formatTs(extractTs(s));
}

// ---- carga de datos ----
async function loadData() {
  error.value = null;
  loadingAlerts.value = true;
  loadingSuspicious.value = true;

  const minutes = windowMinutes.value || WINDOW_MINUTES;

  try {
    const [alertsRes, suspRes] = await Promise.allSettled([
      api.get<any>("/ssh_alerts", { minutes }),
      api.get<any>("/ssh_suspicious_logins", { minutes }),
    ]);

    if (alertsRes.status === "fulfilled") {
      const data = alertsRes.value;
      if (typeof data?.window_minutes === "number") {
        windowMinutes.value = data.window_minutes;
      }

      const rawAlerts =
        data?.alerts ??
        data?.items ??
        data?.events ??
        data?.data ??
        (Array.isArray(data) ? data : []);

      alerts.value = Array.isArray(rawAlerts) ? rawAlerts : [];
    } else {
      console.error("Error cargando ssh_alerts:", alertsRes.reason);
    }

    if (suspRes.status === "fulfilled") {
      const data = suspRes.value;
      if (typeof data?.window_minutes === "number") {
        windowMinutes.value = data.window_minutes;
      }

      const rawSusp =
        data?.items ??
        data?.alerts ??
        data?.events ??
        data?.data ??
        (Array.isArray(data) ? data : []);

      suspiciousLogins.value = Array.isArray(rawSusp) ? rawSusp : [];
    } else {
      console.error(
        "Error cargando ssh_suspicious_logins:",
        suspRes.reason,
      );
    }

    if (
      alertsRes.status === "rejected" &&
      suspRes.status === "rejected"
    ) {
      error.value =
        "No se pudieron obtener ni las alertas SSH ni los logins sospechosos. Revisa el estado del natu-core.";
    }

    lastUpdated.value = new Date();
  } finally {
    loadingAlerts.value = false;
    loadingSuspicious.value = false;
    if (!windowMinutes.value) {
      windowMinutes.value = WINDOW_MINUTES;
    }
  }
}

async function refreshData() {
  await loadData();
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
    void refreshData();
  }, selectedInterval.value * 1000);
}

watch([selectedInterval, autoRefreshEnabled], () => {
  setupAutoRefresh();
});

watch(windowMinutes, () => {
  void refreshData();
});

function openDetail(title: string, evt: any) {
  detailTitle.value = title;
  detailSubtitle.value = "Evento enviado por natu-core";
  detailEvent.value = evt;
  showDetail.value = true;
}

onMounted(() => {
  void refreshData();
  setupAutoRefresh();
});

onBeforeUnmount(() => {
  clearAutoRefresh();
});
</script>

<style scoped>
.row--clickable {
  cursor: pointer;
}

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
</style>
