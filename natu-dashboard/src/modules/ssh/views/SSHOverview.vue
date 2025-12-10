<template>
  <div class="page">
    <header class="page-header">
      <h1 class="page-header__title">SSH · Resumen de actividad</h1>
      <p class="page-header__subtitle">
        Accesos recientes, intentos fallidos y distribución por IP/usuario para el servidor isov3.
      </p>
      <div class="tabs">
        <span class="tab tab-active">SSH (resumen)</span>
        <a href="/ssh/activity" class="tab">SSH (actividad)</a>
        <a href="/ssh/alerts" class="tab">Alertas SSH</a>
        <a href="/ssh/sudo" class="tab">Sudo (actividad)</a>
        <a href="/ssh/sudo-alerts" class="tab">Alertas sudo</a>
      </div>
    </header>

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
      <!-- Selector de ventana -->
      <div class="window-selector">
        <span class="window-selector__label">Ventana:</span>
        <button
          v-for="m in windowOptions"
          :key="m"
          type="button"
          class="window-selector__btn"
          :class="{
            'window-selector__btn--active': selectedWindow === m
          }"
          @click="onChangeWindow(m)"
        >
          <span v-if="m >= 1440">{{ m / 1440 }} día(s)</span>
          <span v-else>{{ m }} min</span>
        </button>
      </div>

      <!-- Cards resumen -->
      <div class="stats-grid">
        <StatCard
          title="Ventana analizada"
          :value="windowLabel"
          subtitle="Parámetro minutes en /api/v1/ssh_summary"
        />

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
              >
                <td>{{ idx + 1 }}</td>
                <td>{{ ip.remote_ip || ip.ip || "-" }}</td>
                <td>{{ ip.failed ?? ip.failed_count ?? "-" }}</td>
              </tr>
              <tr v-if="topIps.length === 0">
                <td colspan="3" style="font-size: 0.78rem; color: #9ca3af;">
                  No se han registrado intentos fallidos en la ventana seleccionada.
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
              >
                <td>{{ idx + 1 }}</td>
                <td>{{ u.username }}</td>
                <td>{{ u.failed ?? 0 }}</td>
                <td>{{ u.success ?? 0 }}</td>
              </tr>
              <tr v-if="topUsers.length === 0">
                <td colspan="4" style="font-size: 0.78rem; color: #9ca3af;">
                  No se han registrado usuarios en la ventana seleccionada.
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Timeline genérico (top IPs) -->
      <section style="margin-top: 1rem;">
        <div class="table-card">
          <div class="table-card__title">
            Timeline SSH (top IPs) — últimos {{ windowMinutes ?? selectedWindow }} min
          </div>

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
                  v-for="(e, idx) in aggregatedTimelineEvents"
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
                    No hay IPs con intentos fallidos en la ventana seleccionada.
                    El timeline genérico se construye a partir de las IPs más
                    activas en <strong>SSH failed</strong>. Para ver solo tus
                    logins exitosos necesitaremos extender el natu-core más
                    adelante.
                  </td>
                </tr>

                <tr
                  v-else-if="
                    topIps.length > 0 && aggregatedTimelineEvents.length === 0
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
import { onMounted, ref, computed } from "vue";
import { api } from "../../../services/api";
import StatCard from "../../../components/shared/StatCard.vue";
import LoadingSpinner from "../../../components/shared/LoadingSpinner.vue";
import EventDetailDrawer from "../../../components/shared/EventDetailDrawer.vue";

const WINDOW_MINUTES = 240;

// opciones de ventana (minutos)
const windowOptions = [60, 240, 1440];
const MAX_TIMELINE_IPS = 5;

// estado resumen
const loadingSummary = ref(true);
const errorSummary = ref<string | null>(null);
const windowMinutes = ref<number | null>(null);
const selectedWindow = ref<number>(WINDOW_MINUTES);
const failedTotal = ref<number>(0);
const successTotal = ref<number>(0);
const hostsCount = ref<number>(0);
const topIps = ref<any[]>([]);
const topUsers = ref<any[]>([]);

// timeline agregado
const loadingTimeline = ref(false);
const errorTimeline = ref<string | null>(null);
const aggregatedTimelineEvents = ref<any[]>([]);

// detalle
const showDetail = ref(false);
const detailEvent = ref<any | null>(null);
const detailTitle = ref("Detalle evento SSH");
const detailSubtitle = ref("Timeline SSH (top IPs)");

const windowLabel = computed(
  () => `${windowMinutes.value ?? selectedWindow.value} min`,
);

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
    const res = await api.get<any>("/ssh_summary", {
      minutes: selectedWindow.value,
    });

    if (typeof res?.window_minutes === "number") {
      windowMinutes.value = res.window_minutes;
    } else {
      windowMinutes.value = selectedWindow.value;
    }

    const hosts = Array.isArray(res?.hosts) ? res.hosts : [];
    hostsCount.value = hosts.length;

    failedTotal.value = hosts.reduce(
      (acc: number, h: any) => acc + (h.failed ?? 0),
      0,
    );
    successTotal.value = hosts.reduce(
      (acc: number, h: any) => acc + (h.success ?? 0),
      0,
    );

    const ips =
      res?.top_ips ??
      res?.ips ??
      res?.top_sources ??
      (Array.isArray(res) ? res : []);
    topIps.value = Array.isArray(ips) ? ips : [];

    const users =
      res?.top_users ??
      res?.users ??
      res?.top_usernames ??
      (Array.isArray(res) ? res : []);
    topUsers.value = Array.isArray(users) ? users : [];

    // timeline se recalcula cada vez que cambia el resumen
    await loadAggregatedTimeline();
  } catch (e: any) {
    errorSummary.value = e?.message ?? String(e);
  } finally {
    loadingSummary.value = false;
  }
}

async function loadAggregatedTimeline() {
  aggregatedTimelineEvents.value = [];

  if (!topIps.value.length) {
    // no hay IPs de referencia, no podemos construir timeline genérico
    return;
  }

  loadingTimeline.value = true;
  errorTimeline.value = null;

  try {
    const minutes = windowMinutes.value ?? selectedWindow.value;

    const ips = topIps.value
      .map((r: any) => r.remote_ip || r.ip)
      .filter(Boolean)
      .slice(0, MAX_TIMELINE_IPS);

    const promises = ips.map((ip: string) =>
      api
        .get<any>("/ssh_timeline", {
          minutes,
          ip,
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

    aggregatedTimelineEvents.value = merged;
  } catch (e: any) {
    errorTimeline.value = e?.message ?? String(e);
    aggregatedTimelineEvents.value = [];
  } finally {
    loadingTimeline.value = false;
  }
}

async function onChangeWindow(minutes: number) {
  if (selectedWindow.value === minutes) return;
  selectedWindow.value = minutes;
  await loadSummary();
}

function openDetail(title: string, evt: any) {
  detailTitle.value = title;
  detailSubtitle.value = "Timeline SSH (top IPs agregadas)";
  detailEvent.value = evt;
  showDetail.value = true;
}

onMounted(() => {
  void loadSummary();
});
</script>

<style scoped>
.row--clickable {
  cursor: pointer;
}

/* Selector de ventana */
.window-selector {
  display: flex;
  justify-content: flex-end;
  align-items: center;
  gap: 0.4rem;
  margin-bottom: 0.65rem;
}

.window-selector__label {
  font-size: 0.72rem;
  color: #9ca3af;
}

.window-selector__btn {
  border-radius: 9999px;
  border: 1px solid rgba(148, 163, 184, 0.35);
  background: rgba(15, 23, 42, 0.9);
  padding: 0.15rem 0.65rem;
  font-size: 0.75rem;
  color: #e5e7eb;
  cursor: pointer;
}

.window-selector__btn--active {
  background: linear-gradient(90deg, #2563eb, #4f46e5);
  border-color: transparent;
}
</style>
