<template>
  <div class="page">
    <div class="page-sticky">
      <header class="page-header">
        <h1 class="page-header__title">Sudo · Resumen</h1>
        <p class="page-header__subtitle">
          Visión general de ejecuciones sudo, usuarios y comandos elevados en el
          servidor isov3.
        </p>
        <div class="tabs">
          <a href="/ssh" class="tab">SSH (resumen)</a>
          <a href="/ssh/activity" class="tab">SSH (actividad)</a>
          <a href="/ssh/alerts" class="tab">Alertas SSH</a>
          <a href="/ssh/reactividad" class="tab">Reactividad</a>
          <span class="tab tab-active">Sudo (resumen)</span>
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

    <!-- Filtros -->
    <section class="page" style="margin-bottom: 0.75rem;">
      <form class="filters-bar" @submit.prevent="onApplyFilters">
        <div class="filters-bar__group">
          <label class="filters-bar__label">
            Usuario sudo (<code>sudo_user</code>)
          </label>
          <input
            v-model="sudoUser"
            class="filters-bar__input"
            type="text"
            placeholder="Ej: root"
          />
        </div>

        <div class="filters-bar__group">
          <label class="filters-bar__label">
            <span>target_user</span>
            <span class="filters-bar__label-badge">opcional</span>
          </label>
          <input
            v-model="targetUser"
            class="filters-bar__input"
            type="text"
            placeholder="Ej: root"
          />
        </div>

        <div class="filters-bar__actions">
          <button type="submit" class="btn-primary">
            Aplicar filtros
          </button>
        </div>
      </form>
      <p class="filters-bar__hint">
        El endpoint <code>/api/v1/sudo_timeline</code> requiere al menos
        <code>sudo_user</code> o <code>target_user</code>. Si no indicas nada,
        se usará <strong>sudo_user = "root"</strong>.
      </p>
    </section>

    <!-- Estado: cargando -->
    <section v-if="loading" class="section--loading">
      <LoadingSpinner /> Cargando actividad de sudo...
    </section>

    <!-- Estado: error -->
    <section v-else-if="error" class="section--error">
      Error al cargar datos de sudo: {{ error }}
    </section>

    <!-- Datos OK -->
    <section v-else class="page">
      <!-- Cards resumen -->
      <div class="stats-grid">
        <StatCard
          title="Ejecuciones sudo"
          :value="events.length"
          subtitle="Total de eventos sudo registrados"
        />

        <StatCard
          title="Usuarios con sudo"
          :value="usersSummary.length"
          subtitle="Cantidad de usuarios (sudo_user) que usaron sudo"
        />

        <StatCard
          title="Comandos distintos"
          :value="distinctCommands"
          subtitle="Número aproximado de binarios/comandos usados con sudo"
        />

        <StatCard
          title="Hosts monitoreados"
          :value="hostsCount"
          subtitle="Agentes/hosts que enviaron eventos sudo"
        />
      </div>

      <!-- Mensaje si no hay datos -->
      <section
        v-if="events.length === 0"
        class="section--loading"
        style="margin-top: 0.9rem;"
      >
        No se han registrado ejecuciones sudo en la ventana seleccionada
        para los filtros actuales.
      </section>

      <section
        v-else
        class="page"
        style="margin-top: 0.9rem;"
      >
        <div class="tables-grid">
          <!-- Top usuarios sudo -->
          <div class="table-card">
            <div class="table-card__title">Top usuarios usando sudo</div>
            <table class="table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Usuario</th>
                  <th>Comandos sudo</th>
                  <th>Último uso</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="(u, idx) in usersSummary"
                  :key="u.username + '-' + idx"
                  class="row--clickable"
                  @click="openDetail(u, 'Top usuarios usando sudo', 'Usuario sudo')"
                >
                  <td>{{ idx + 1 }}</td>
                  <td>{{ u.username }}</td>
                  <td>{{ u.count }}</td>
                  <td>{{ formatTs(u.lastTs) }}</td>
                </tr>
              </tbody>
            </table>
          </div>

          <!-- Actividad sudo cruda -->
          <div class="table-card">
            <div class="table-card__title">Actividad sudo (últimos eventos)</div>
            <table class="table">
              <thead>
                <tr>
                  <th>Fecha/Hora</th>
                  <th>Host</th>
                  <th>IP</th>
                  <th>sudo_user</th>
                  <th>target_user</th>
                  <th>Comando</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="(e, idx) in events"
                  :key="idx"
                  class="row--clickable"
                  @click="openDetail(e)"
                >
                  <td>{{ formatTs(e.ts || e.timestamp || e.time || "") }}</td>
                  <td>{{ e.hostname || e.host || "-" }}</td>
                  <td>{{ e.remote_ip || e.ip || e.source_ip || "-" }}</td>
                  <td>{{ e.sudo_user || e.username || e.user || "-" }}</td>
                  <td>{{ e.target_user || "-" }}</td>
                  <td>{{ e.command || e.cmd || e.binary || "-" }}</td>
                </tr>
              </tbody>
            </table>
          </div>
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
import { computed, onMounted, ref } from "vue";
import { api } from "../../../services/api";
import StatCard from "../../../components/shared/StatCard.vue";
import LoadingSpinner from "../../../components/shared/LoadingSpinner.vue";
import EventDetailDrawer from "../../../components/shared/EventDetailDrawer.vue";

const loading = ref(true);
const error = ref<string | null>(null);
const windowMinutes = ref<number>(240);
const lastUpdated = ref<Date | null>(null);
const intervalOptions = [3, 5, 15, 30, 60];
const selectedInterval = ref<number>(5);
const autoRefreshEnabled = ref<boolean>(true);
let refreshTimer: number | undefined;

const events = ref<any[]>([]);

// filtros
const sudoUser = ref<string>("root");
const targetUser = ref<string>("");

// detalle
const showDetail = ref(false);
const detailEvent = ref<any | null>(null);
const detailTitle = ref("Detalle de ejecución sudo");
const detailSubtitle = ref("Evento enviado por /api/v1/sudo_timeline");

// por ahora fijo; luego configurable
const WINDOW_MINUTES = 240;

const usersSummary = computed(() => {
  const map = new Map<
    string,
    { username: string; count: number; lastTs: string }
  >();

  for (const e of events.value) {
    const username =
      (e.sudo_user || e.username || e.user || "desconocido") as string;
    const ts = (e.ts || e.timestamp || e.time || "") as string;

    const current = map.get(username) ?? {
      username,
      count: 0,
      lastTs: "",
    };

    current.count += 1;

    if (ts) {
      const dCurrent = new Date(ts).getTime();
      const dLast = current.lastTs ? new Date(current.lastTs).getTime() : 0;
      if (dCurrent > dLast) current.lastTs = ts;
    }

    map.set(username, current);
  }

  return Array.from(map.values()).sort((a, b) => b.count - a.count);
});

const distinctCommands = computed(() => {
  const set = new Set<string>();
  for (const e of events.value) {
    const cmd = (e.command || e.cmd || e.binary) as string | undefined;
    if (cmd) set.add(cmd);
  }
  return set.size;
});

const hostsCount = computed(() => {
  const set = new Set<string>();
  for (const e of events.value) {
    const host = (e.hostname || e.host || "") as string;
    if (host) set.add(host);
  }
  return set.size;
});

const lastUpdatedLabel = computed(() => {
  if (!lastUpdated.value) return "—";
  return lastUpdated.value.toLocaleTimeString();
});

function formatTs(ts: string): string {
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts || "—";
  return d.toLocaleString();
}

async function loadData() {
  loading.value = true;
  error.value = null;

  try {
    const params: Record<string, any> = {
      minutes: windowMinutes.value || WINDOW_MINUTES,
    };

    if (sudoUser.value || targetUser.value) {
      if (sudoUser.value) params.sudo_user = sudoUser.value;
      if (targetUser.value) params.target_user = targetUser.value;
    } else {
      params.sudo_user = "root";
    }

    const res = await api.get<any>("/sudo_timeline", params);

    if (typeof res?.window_minutes === "number") {
      windowMinutes.value = res.window_minutes;
    } else {
      windowMinutes.value = WINDOW_MINUTES;
    }

    const rawEvents =
      res?.events ??
      res?.items ??
      res?.points ??
      res?.data ??
      (Array.isArray(res) ? res : []);

    events.value = Array.isArray(rawEvents) ? rawEvents : [];
    lastUpdated.value = new Date(res?.generated_at ?? Date.now());
  } catch (e: any) {
    error.value = e?.message ?? String(e);
    events.value = [];
  } finally {
    loading.value = false;
    if (!windowMinutes.value) {
      windowMinutes.value = WINDOW_MINUTES;
    }
  }
}

function refreshData(manual = false) {
  void loadData();
  if (manual) {
    clearAutoRefresh();
    scheduleAutoRefresh();
  }
}

function clearAutoRefresh() {
  if (refreshTimer) {
    window.clearInterval(refreshTimer);
    refreshTimer = undefined;
  }
}

function scheduleAutoRefresh() {
  clearAutoRefresh();
  if (!autoRefreshEnabled.value) return;
  refreshTimer = window.setInterval(() => {
    void loadData();
  }, selectedInterval.value * 1000);
}

function onApplyFilters() {
  void refreshData();
}

function openDetail(
  e: any,
  subtitle = "Evento enviado por /api/v1/sudo_timeline",
  title = "Detalle de ejecución sudo",
) {
  detailEvent.value = e;
  detailSubtitle.value = subtitle;
  detailTitle.value = title;
  showDetail.value = true;
}
onMounted(() => {
  void refreshData(true);
  scheduleAutoRefresh();
});

onBeforeUnmount(() => {
  clearAutoRefresh();
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
  gap: 0.5rem;
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

.filters-bar {
  display: flex;
  gap: 1rem;
  align-items: flex-end;
  padding: 0.75rem 1rem;
  border-radius: 0.75rem;
  border: 1px solid rgba(148, 163, 184, 0.16);
  background: radial-gradient(
      circle at top left,
      rgba(56, 189, 248, 0.08),
      transparent
    ),
    rgba(15, 23, 42, 0.9);
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
  display: flex;
  align-items: center;
  gap: 0.35rem;
}

.filters-bar__label-badge {
  font-size: 0.65rem;
  padding: 0.05rem 0.45rem;
  border-radius: 9999px;
  border: 1px solid rgba(148, 163, 184, 0.4);
  color: #9ca3af;
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

.btn-primary {
  border-radius: 9999px;
  border: none;
  padding: 0.4rem 0.9rem;
  font-size: 0.8rem;
  background: linear-gradient(90deg, #2563eb, #4f46e5);
  color: #f9fafb;
  cursor: pointer;
  white-space: nowrap;
}

.btn-primary:hover {
  filter: brightness(1.08);
}

.filters-bar__hint {
  margin-top: 0.4rem;
  font-size: 0.68rem;
  color: #9ca3af;
}
</style>
