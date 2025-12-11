<template>
  <div class="page">
    <header class="page-header">
      <h1 class="page-header__title">SSH · Reactividad</h1>
      <p class="page-header__subtitle">
        Eventos de baneo/desbaneo desde Fail2ban + ipset para el módulo SSH (isov3).
      </p>
      <div class="tabs">
        <a href="/ssh" class="tab">SSH (resumen)</a>
        <a href="/ssh/activity" class="tab">SSH (actividad)</a>
        <a href="/ssh/alerts" class="tab">Alertas SSH</a>
        <a href="/ssh/sudo" class="tab">Sudo (actividad)</a>
        <a href="/ssh/sudo-alerts" class="tab">Alertas sudo</a>
        <a href="/ssh/criticality" class="tab">Criticidad</a>
        <span class="tab tab-active">Reactividad</span>
      </div>
    </header>

    <section class="page" style="gap: 1rem; display: flex; flex-direction: column;">
      <div class="stats-grid">
        <StatCard
          title="Fuente"
          value="/var/log/fail2ban.log"
          subtitle="Fail2ban registra ban/unban y se usa como feed principal"
        />
        <StatCard
          title="Enforcement"
          value="ipset ssh-banned"
          subtitle="UFW aplica DROP de la lista gestionada por Fail2ban"
        />
        <StatCard
          title="Payload sugerido"
          value="{ts, jail, action, ip}"
          subtitle="Emitido por la API/agent al Tab Reactividad"
        />
      </div>

      <div class="tables-grid">
        <div class="table-card">
          <div class="table-card__title">Eventos recientes (ejemplo)</div>
          <table class="table">
            <thead>
              <tr>
                <th>Fecha/Hora (UTC)</th>
                <th>Jail</th>
                <th>Acción</th>
                <th>IP</th>
                <th>Fuente</th>
                <th>Detalle</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(event, idx) in sampleEvents" :key="idx">
                <td>{{ event.ts }}</td>
                <td>{{ event.jail }}</td>
                <td>
                  <span :class="event.action === 'Ban' ? 'pill pill-danger' : 'pill pill-neutral'">
                    {{ event.action }}
                  </span>
                </td>
                <td>{{ event.ip }}</td>
                <td>{{ event.source }}</td>
                <td>{{ event.note }}</td>
              </tr>
            </tbody>
          </table>
          <p class="table-card__hint">
            Estos eventos se obtienen parseando líneas como: "2024-05-27 ... [sshd] Ban 172.236.228.208" en
            <code>/var/log/fail2ban.log</code>. El agente puede usar <code>tail -F</code> o <code>journalctl -u fail2ban</code>.
          </p>
        </div>

        <div class="table-card">
          <div class="table-card__title">Flujo propuesto para el Tab</div>
          <ol class="list">
            <li>
              <strong>Lectura</strong>: natu-agente observa el log de Fail2ban con seguimiento de rotación.
            </li>
            <li>
              <strong>Parseo</strong>: extrae <code>timestamp</code>, <code>jail</code>, <code>action (Ban/Unban)</code>,
              <code>ip</code> y el origen <code>fail2ban</code>.
            </li>
            <li>
              <strong>Publicación</strong>: envía cada evento a la API que consumirá este Tab con el payload JSON sugerido.
            </li>
            <li>
              <strong>Visualización</strong>: la UI muestra cronológicamente los eventos y destaca los Ban activos.
            </li>
          </ol>
          <p class="table-card__hint">
            El set <code>ssh-banned</code> ya se aplica vía UFW, por lo que este Tab solo consume datos; no necesita privilegios
            adicionales.
          </p>
        </div>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import StatCard from "../../../components/shared/StatCard.vue";

interface ReactivityEvent {
  ts: string;
  jail: string;
  action: "Ban" | "Unban";
  ip: string;
  source: string;
  note: string;
}

const sampleEvents: ReactivityEvent[] = [
  {
    ts: "2024-05-27 15:31:42",
    jail: "sshd",
    action: "Ban",
    ip: "172.236.228.208",
    source: "fail2ban",
    note: "Exceso de intentos fallidos detectado por la jail sshd",
  },
  {
    ts: "2024-05-27 15:35:42",
    jail: "sshd",
    action: "Unban",
    ip: "172.236.228.208",
    source: "fail2ban",
    note: "Bantime expirado, ipset ssh-banned limpio",
  },
  {
    ts: "2024-05-27 15:45:11",
    jail: "sshd",
    action: "Ban",
    ip: "203.0.113.10",
    source: "fail2ban",
    note: "Conexiones repetidas con credenciales inválidas",
  },
];
</script>

<style scoped>
.page {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.page-header__subtitle {
  max-width: 960px;
}

.table-card__hint {
  margin-top: 0.75rem;
  color: #9ca3af;
  font-size: 0.85rem;
  line-height: 1.5;
}

.list {
  color: #e5e7eb;
  line-height: 1.5;
  padding-left: 1rem;
}

.list li {
  margin-bottom: 0.5rem;
}

.pill {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  padding: 0.2rem 0.55rem;
  border-radius: 9999px;
  font-size: 0.75rem;
}

.pill-danger {
  background: rgba(239, 68, 68, 0.18);
  color: #fecdd3;
}

.pill-neutral {
  background: rgba(148, 163, 184, 0.18);
  color: #e5e7eb;
}
</style>
