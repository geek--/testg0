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
      <div class="activity-toolbar activity-toolbar--wide">
        <div class="activity-toolbar__group activity-toolbar__group--inline">
          <div class="activity-toolbar__inline-field">
            <label class="activity-toolbar__label">Ventana (min)</label>
            <input
              v-model.number="windowMinutes"
              class="activity-toolbar__input"
              type="number"
              min="30"
              max="10080"
            />
          </div>

          <div class="activity-toolbar__inline-field">
            <label class="activity-toolbar__label">Auto-refresco</label>
            <select v-model.number="selectedInterval" class="activity-toolbar__input">
              <option v-for="opt in intervalOptions" :key="opt" :value="opt">
                Cada {{ opt }}s
              </option>
            </select>
          </div>

          <label class="activity-toolbar__toggle">
            <input type="checkbox" v-model="autoRefreshEnabled" />
            <span>Auto</span>
          </label>
          <button class="btn-secondary" type="button" @click="refreshData()">
            Refrescar ahora
          </button>
          <span class="activity-toolbar__hint">Actualizado: {{ lastUpdatedLabel }}</span>
        </div>

        <div class="activity-toolbar__group activity-toolbar__group--filters">
          <span class="activity-toolbar__label">Capas en el termómetro</span>
          <div class="filter-chips">
            <label class="filter-chip">
              <input type="checkbox" v-model="filters.alerts" />
              Alertas SSH
            </label>
            <label class="filter-chip">
              <input type="checkbox" v-model="filters.suspicious" />
              Logins sospechosos
            </label>
            <label class="filter-chip">
              <input type="checkbox" v-model="filters.sudo" />
              Alertas sudo
            </label>
            <label class="filter-chip">
              <input type="checkbox" v-model="filters.activity" />
              Actividad SSH
            </label>
          </div>
        </div>
      </div>

      <section v-if="loading" class="section--loading">
        <LoadingSpinner /> Calculando nivel de riesgo...
      </section>

      <section v-else-if="error" class="section--error">
        {{ error }}
      </section>

      <template v-else>
        <div class="thermo-layout">
          <div class="thermo-card">
            <div class="thermo-card__header">
              <div>
                <div class="thermo-card__title">Termómetro de criticidad</div>
                <div class="thermo-card__subtitle">
                  Pondera alertas, logins sospechosos y actividad reciente en la ventana seleccionada.
                </div>
                <div class="thermo-card__legend-grid">
                  <div v-for="level in legendLevels" :key="level.label" class="legend-pill">
                    <span class="legend-pill__dot" :style="{ background: level.color }"></span>
                    <div>
                      <div class="legend-pill__label">{{ level.label }}</div>
                      <div class="legend-pill__range">{{ level.range }}</div>
                    </div>
                  </div>
                </div>
              </div>
              <div class="gauge">
                <div class="gauge__ring" :style="{ backgroundImage: gaugeGradient }"></div>
                <div class="gauge__center">
                  <div class="gauge__score">{{ riskScore }}%</div>
                  <div class="gauge__label">{{ riskLabel }}</div>
                </div>
              </div>
            </div>
            <div class="thermo">
              <div class="thermo__fill" :style="{ width: riskScore + '%', background: riskColor }"></div>
            </div>
            <div class="thermo-card__legend">
              <strong>{{ riskLabel }}</strong>
              · {{ riskSummary }}
            </div>
          </div>

          <div class="stacked-card">
            <div class="stacked-card__header">
              <div class="stacked-card__title">Contribución por capa</div>
              <div class="stacked-card__subtitle">Distribución ponderada de riesgo</div>
            </div>
            <div class="stacked-bars">
              <div
                v-for="item in contributionBars"
                :key="item.label"
                class="stacked-bar"
              >
                <div class="stacked-bar__label">{{ item.label }}</div>
                <div class="stacked-bar__meter">
                  <div
                    class="stacked-bar__fill"
                    :style="{ width: item.width + '%', background: item.color }"
                  ></div>
                </div>
                <div class="stacked-bar__value">{{ item.valueLabel }}</div>
              </div>
            </div>
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

const filters = ref({
  alerts: true,
  suspicious: true,
  sudo: true,
  activity: true,
});

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
  if (filters.value.alerts) score += Math.min(alerts.value.length * 10, 40);
  if (filters.value.suspicious) score += Math.min(suspiciousLogins.value.length * 12, 30);
  if (filters.value.sudo) score += Math.min(sudoAlerts.value.length * 8, 20);
  if (filters.value.activity) score += Math.min((activityEvents.value.length / 200) * 10, 10);
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

const gaugeGradient = computed(() => {
  return `conic-gradient(${riskColor.value} ${riskScore.value * 3.6}deg, rgba(255,255,255,0.06) ${riskScore.value * 3.6}deg)`;
});

const legendLevels = [
  { label: "Bajo", range: "0-24%", color: "#22c55e" },
  { label: "Moderado", range: "25-49%", color: "#eab308" },
  { label: "Alto", range: "50-74%", color: "#f97316" },
  { label: "Crítico", range: "75-100%", color: "#ef4444" },
];

const contributionBars = computed(() => {
  const entries = [
    {
      label: "Alertas SSH",
      value: filters.value.alerts ? alerts.value.length * 10 : 0,
      max: 40,
      color: "#fb7185",
    },
    {
      label: "Logins sospechosos",
      value: filters.value.suspicious ? suspiciousLogins.value.length * 12 : 0,
      max: 30,
      color: "#facc15",
    },
    {
      label: "Alertas sudo",
      value: filters.value.sudo ? sudoAlerts.value.length * 8 : 0,
      max: 20,
      color: "#34d399",
    },
    {
      label: "Actividad SSH",
      value: filters.value.activity ? (activityEvents.value.length / 200) * 10 : 0,
      max: 10,
      color: "#60a5fa",
    },
  ];

  return entries.map((entry) => {
    const width = Math.min(100, Math.round((entry.value / entry.max) * 100));
    return {
      label: entry.label,
      width,
      color: entry.color,
      valueLabel: `${Math.round(Math.min(entry.value, entry.max))} pts`,
    };
  });
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

.thermo-layout {
  display: grid;
  grid-template-columns: 1.5fr 1fr;
  gap: 1rem;
  align-items: stretch;
}

@media (max-width: 1024px) {
  .thermo-layout {
    grid-template-columns: 1fr;
  }
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

.thermo-card__legend-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 0.5rem;
  margin-top: 0.75rem;
}

.legend-pill {
  display: grid;
  grid-template-columns: auto 1fr;
  align-items: center;
  gap: 0.5rem;
  padding: 0.6rem 0.75rem;
  background: #111827;
  border: 1px solid #1f2937;
  border-radius: 8px;
}

.legend-pill__dot {
  width: 12px;
  height: 12px;
  border-radius: 50%;
}

.legend-pill__label {
  font-weight: 700;
  font-size: 0.9rem;
}

.legend-pill__range {
  font-size: 0.75rem;
  color: #9ca3af;
}

.thermo-card__score {
  font-size: 2rem;
  font-weight: 800;
  color: #e2e8f0;
}

.gauge {
  position: relative;
  width: 150px;
  height: 150px;
  display: grid;
  place-items: center;
}

.gauge__ring {
  width: 150px;
  height: 150px;
  border-radius: 50%;
  background: conic-gradient(#22c55e 0deg, rgba(255, 255, 255, 0.05) 0deg);
  display: grid;
  place-items: center;
  padding: 12px;
  box-shadow: inset 0 0 0 1px #1f2937;
}

.gauge__center {
  width: 100%;
  height: 100%;
  border-radius: 50%;
  background: #0b1220;
  display: grid;
  place-items: center;
  gap: 0.15rem;
  box-shadow: 0 20px 50px rgba(0, 0, 0, 0.3);
}

.gauge__score {
  font-size: 1.9rem;
  font-weight: 800;
}

.gauge__label {
  font-size: 0.9rem;
  color: #9ca3af;
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

.activity-toolbar--wide {
  flex-direction: column;
  gap: 0.75rem;
}

.activity-toolbar__group--inline {
  display: flex;
  flex-wrap: wrap;
  gap: 0.75rem;
  align-items: center;
}

.activity-toolbar__inline-field {
  display: grid;
  gap: 0.25rem;
}

.activity-toolbar__group--filters {
  display: grid;
  gap: 0.25rem;
}

.filter-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.filter-chip {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  padding: 0.35rem 0.65rem;
  background: #111827;
  border: 1px solid #1f2937;
  border-radius: 20px;
  font-size: 0.9rem;
}

.stacked-card {
  background: #0f172a;
  border: 1px solid #1f2937;
  border-radius: 10px;
  padding: 1rem;
  display: grid;
  gap: 0.75rem;
}

.stacked-card__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.stacked-card__title {
  font-weight: 700;
}

.stacked-card__subtitle {
  font-size: 0.85rem;
  color: #9ca3af;
}

.stacked-bars {
  display: grid;
  gap: 0.65rem;
}

.stacked-bar {
  display: grid;
  gap: 0.35rem;
}

.stacked-bar__label {
  font-size: 0.9rem;
  color: #e5e7eb;
}

.stacked-bar__meter {
  width: 100%;
  height: 12px;
  background: #111827;
  border-radius: 8px;
  overflow: hidden;
  border: 1px solid #1f2937;
}

.stacked-bar__fill {
  height: 100%;
  width: 0;
  transition: width 0.35s ease;
}

.stacked-bar__value {
  font-size: 0.85rem;
  color: #9ca3af;
}

.table-empty {
  font-size: 0.82rem;
  color: #9ca3af;
  text-align: center;
}
</style>
