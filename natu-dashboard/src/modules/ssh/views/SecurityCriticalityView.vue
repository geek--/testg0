<template>
  <div class="page">
    <header class="page-header">
      <h1 class="page-header__title">Criticidad · Termómetro de seguridad</h1>
      <p class="page-header__subtitle">
        Vista general del riesgo basado en las alertas de SSH y sudo, logins sospechosos
        y volumen de actividad reciente.
      </p>
      <div class="tabs">
        <a href="/ssh" class="tab">SSH (resumen)</a>
        <a href="/ssh/activity" class="tab">SSH (actividad)</a>
        <a href="/ssh/alerts" class="tab">Alertas SSH</a>
        <a href="/ssh/sudo" class="tab">Sudo (actividad)</a>
        <a href="/ssh/sudo-alerts" class="tab">Alertas sudo</a>
        <span class="tab tab-active">Criticidad</span>
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
            min="30"
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

      <section v-if="loading" class="section--loading">
        <LoadingSpinner /> Calculando nivel de riesgo...
      </section>

      <section v-else-if="error" class="section--error">
        {{ error }}
      </section>

      <template v-else>
        <div class="thermo-card">
          <div class="thermo-card__header">
            <div>
              <div class="thermo-card__title">Termómetro de criticidad</div>
              <div class="thermo-card__subtitle">
                Pondera alertas, logins sospechosos y actividad reciente en la ventana seleccionada.
              </div>
            </div>
            <div class="thermo-card__score">{{ riskScore }}%</div>
          </div>
          <div class="thermo">
            <div class="thermo__fill" :style="{ width: riskScore + '%', background: riskColor }"></div>
          </div>
          <div class="thermo-card__legend">
            <strong>{{ riskLabel }}</strong>
            · {{ riskSummary }}
          </div>
        </div>

        <div class="stats-grid">
          <StatCard
            title="Alertas SSH"
            :value="alerts.length"
            subtitle="Detectadas por fuerza bruta o actividad inusual"
          />
          <StatCard
            title="Logins sospechosos"
            :value="suspiciousLogins.length"
            subtitle="Accesos exitosos tras intentos fallidos"
          />
          <StatCard
            title="Alertas sudo"
            :value="sudoAlerts.length"
            subtitle="Comandos peligrosos ejecutados con sudo"
          />
          <StatCard
            title="Eventos SSH recientes"
            :value="recentActivity"
            subtitle="Muestra presión de autenticación en la ventana"
          />
        </div>

        <div class="tables-grid" style="margin-top: 1rem;">
          <div class="table-card">
            <div class="table-card__title">Alertas más recientes</div>
            <table class="table">
              <thead>
                <tr>
                  <th>Fecha/Hora</th>
                  <th>Host</th>
                  <th>IP</th>
                  <th>Usuario</th>
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
                  <td>{{ formatTs(a.created_at || a.ts || a.time || "") }}</td>
                  <td>{{ a.hostname || a.host || "-" }}</td>
                  <td>{{ a.remote_ip || a.ip || a.source_ip || "-" }}</td>
                  <td>{{ a.username || a.user || "-" }}</td>
                  <td>{{ a.severity || a.level || "-" }}</td>
                  <td>{{ a.message || a.msg || a.description || "-" }}</td>
                </tr>
                <tr v-if="alerts.length === 0">
                  <td colspan="6" class="table-empty">No hay alertas SSH en la ventana.</td>
                </tr>
              </tbody>
            </table>
          </div>

          <div class="table-card">
            <div class="table-card__title">Eventos de seguridad destacados</div>
            <table class="table">
              <thead>
                <tr>
                  <th>Fecha/Hora</th>
                  <th>Tipo</th>
                  <th>Host</th>
                  <th>IP/Usuario</th>
                  <th>Detalle</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="(ev, idx) in spotlightEvents"
                  :key="idx"
                  class="row--clickable"
                  @click="openDetail(ev.label, ev.payload)"
                >
                  <td>{{ formatTs(ev.ts) }}</td>
                  <td>{{ ev.label }}</td>
                  <td>{{ ev.host }}</td>
                  <td>{{ ev.identity }}</td>
                  <td>{{ ev.summary }}</td>
                </tr>
                <tr v-if="spotlightEvents.length === 0">
                  <td colspan="5" class="table-empty">Sin hallazgos adicionales en la ventana.</td>
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

const alerts = ref<any[]>([]);
const suspiciousLogins = ref<any[]>([]);
const sudoAlerts = ref<any[]>([]);
const activityEvents = ref<any[]>([]);
const lastUpdated = ref<Date | null>(null);
const loading = ref<boolean>(true);
const error = ref<string | null>(null);

const windowMinutes = ref<number>(240);
const intervalOptions = [5, 10, 30, 60];
const selectedInterval = ref<number>(30);
const autoRefreshEnabled = ref<boolean>(true);
let refreshHandle: number | null = null;

const showDetail = ref(false);
const detailEvent = ref<any | null>(null);
const detailTitle = ref("Detalle");
const detailSubtitle = ref("");

const recentActivity = computed(() => activityEvents.value.length);

const lastUpdatedLabel = computed(() => {
  if (!lastUpdated.value) return "-";
  return new Intl.DateTimeFormat("es-ES", {
    dateStyle: "short",
    timeStyle: "medium",
  }).format(lastUpdated.value);
});

const riskScore = computed(() => {
  let score = 0;
  score += Math.min(alerts.value.length * 10, 40);
  score += Math.min(suspiciousLogins.value.length * 12, 30);
  score += Math.min(sudoAlerts.value.length * 8, 20);
  score += Math.min(activityEvents.value.length / 200 * 10, 10);
  return Math.round(Math.min(100, score));
});

const riskLabel = computed(() => {
  if (riskScore.value >= 75) return "Crítico";
  if (riskScore.value >= 50) return "Alto";
  if (riskScore.value >= 25) return "Moderado";
  return "Bajo";
});

const riskColor = computed(() => {
  if (riskScore.value >= 75) return "#ef4444";
  if (riskScore.value >= 50) return "#f97316";
  if (riskScore.value >= 25) return "#eab308";
  return "#22c55e";
});

const riskSummary = computed(() => {
  return `Alertas SSH: ${alerts.value.length} · Logins sospechosos: ${suspiciousLogins.value.length} · Alertas sudo: ${sudoAlerts.value.length}`;
});

const spotlightEvents = computed(() => {
  const highlights: Array<{
    ts: string;
    label: string;
    host: string;
    identity: string;
    summary: string;
    payload: any;
  }> = [];

  for (const a of alerts.value.slice(0, 3)) {
    highlights.push({
      ts: a.created_at || a.ts || a.time || new Date().toISOString(),
      label: "Alerta SSH",
      host: a.hostname || a.host || "-",
      identity: a.remote_ip || a.ip || "-",
      summary:
        a.message ||
        `Fuerza bruta (${a.failed_count ?? a.count ?? "?"} intentos) desde ${a.remote_ip}`,
      payload: a,
    });
  }

  for (const s of suspiciousLogins.value.slice(0, 2)) {
    highlights.push({
      ts: s.success_at || s.created_at || s.ts || new Date().toISOString(),
      label: "Login sospechoso",
      host: s.hostname || s.host || "-",
      identity: `${s.username || s.user || "-"} @ ${s.remote_ip || s.ip || "-"}`,
      summary:
        `Acceso exitoso tras ${s.failed_before_count || s.failed_count || s.previous_failures || "?"} fallos`,
      payload: s,
    });
  }

  for (const sa of sudoAlerts.value.slice(0, 2)) {
    highlights.push({
      ts: sa.sudo_ts || sa.created_at || sa.ts || new Date().toISOString(),
      label: "Alerta sudo",
      host: sa.hostname || sa.host || "-",
      identity: `${sa.sudo_user || sa.user || "-"} → ${sa.target_user || "-"}`,
      summary: sa.command || sa.cmd || sa.binary || "Comando sensible",
      payload: sa,
    });
  }

  return highlights.sort((a, b) => (a.ts > b.ts ? -1 : 1));
});

function formatTs(value: string) {
  if (!value) return "-";
  return new Intl.DateTimeFormat("es-ES", {
    dateStyle: "short",
    timeStyle: "medium",
  }).format(new Date(value));
}

async function refreshData() {
  loading.value = true;
  error.value = null;
  try {
    const [alertsRes, suspiciousRes, sudoRes, activityRes] = await Promise.allSettled([
      api.get<any>("/ssh_alerts", { minutes: windowMinutes.value }),
      api.get<any>("/ssh_suspicious_logins", { minutes: windowMinutes.value }),
      api.get<any>("/sudo_alerts", { minutes: windowMinutes.value }),
      api.get<any>("/ssh_activity", { minutes: windowMinutes.value, limit: 200 }),
    ]);

    if (alertsRes.status === "fulfilled") alerts.value = alertsRes.value.alerts ?? [];
    else console.error("Error cargando ssh_alerts:", alertsRes.reason);

    if (suspiciousRes.status === "fulfilled")
      suspiciousLogins.value = suspiciousRes.value.items ?? [];
    else console.error("Error cargando ssh_suspicious_logins:", suspiciousRes.reason);

    if (sudoRes.status === "fulfilled") sudoAlerts.value = sudoRes.value.alerts ?? [];
    else console.error("Error cargando sudo_alerts:", sudoRes.reason);

    if (activityRes.status === "fulfilled") activityEvents.value = activityRes.value.events ?? [];
    else console.error("Error cargando ssh_activity:", activityRes.reason);

    lastUpdated.value = new Date();
  } catch (e: any) {
    error.value = e?.message ?? "Error cargando criticidad";
  } finally {
    loading.value = false;
  }
}

function openDetail(title: string, payload: any) {
  detailEvent.value = payload;
  detailTitle.value = title;
  detailSubtitle.value = payload?.message || payload?.summary || payload?.command || "";
  showDetail.value = true;
}

function startAutoRefresh() {
  stopAutoRefresh();
  if (!autoRefreshEnabled.value) return;
  refreshHandle = window.setInterval(() => refreshData(), selectedInterval.value * 1000);
}

function stopAutoRefresh() {
  if (refreshHandle) {
    clearInterval(refreshHandle);
    refreshHandle = null;
  }
}

watch([selectedInterval, autoRefreshEnabled], () => startAutoRefresh());

watch(windowMinutes, () => {
  refreshData();
});

onMounted(() => {
  refreshData();
  startAutoRefresh();
});

onBeforeUnmount(() => {
  stopAutoRefresh();
});
</script>

<style scoped>
.thermo-card {
  background: #0f172a;
  border: 1px solid #1f2937;
  border-radius: 10px;
  padding: 1rem;
  margin-bottom: 1rem;
}

.thermo-card__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
}

.thermo-card__title {
  font-size: 1.1rem;
  font-weight: 700;
}

.thermo-card__subtitle {
  font-size: 0.9rem;
  color: #9ca3af;
}

.thermo-card__score {
  font-size: 2rem;
  font-weight: 800;
  color: #e2e8f0;
}

.thermo {
  position: relative;
  width: 100%;
  height: 16px;
  background: #1f2937;
  border-radius: 8px;
  overflow: hidden;
  margin: 0.75rem 0;
}

.thermo__fill {
  position: absolute;
  left: 0;
  top: 0;
  bottom: 0;
  width: 0;
  border-radius: 8px;
  transition: width 0.4s ease;
}

.thermo-card__legend {
  font-size: 0.95rem;
  color: #e5e7eb;
}

.table-empty {
  font-size: 0.82rem;
  color: #9ca3af;
  text-align: center;
}
</style>
