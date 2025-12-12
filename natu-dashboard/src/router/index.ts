// src/router/index.ts
import { createRouter, createWebHistory } from "vue-router";
import type { RouteRecordRaw } from "vue-router";

import SSHOverview from "../modules/ssh/views/SSHOverview.vue";
import SSHActivityView from "../modules/ssh/views/SSHActivityView.vue";
import SSHAlertsView from "../modules/ssh/views/SSHAlertsView.vue";
import SudoOverviewView from "../modules/ssh/views/SudoOverviewView.vue";
import SudoActivityView from "../modules/ssh/views/SudoActivityView.vue";
import SudoAlertsView from "../modules/ssh/views/SudoAlertsView.vue";
import SecurityCriticalityView from "../modules/ssh/views/SecurityCriticalityView.vue";
import SSHReactivityView from "../modules/ssh/views/SSHReactivityView.vue";

const routes: RouteRecordRaw[] = [
  {
    path: "/",
    redirect: "/ssh",
  },
  {
    path: "/ssh",
    name: "ssh-overview",
    component: SSHOverview,
  },
  {
    path: "/ssh/activity",
    name: "ssh-activity",
    component: SSHActivityView,
  },
  {
    path: "/ssh/alerts",
    name: "ssh-alerts",
    component: SSHAlertsView,
  },
  {
    path: "/ssh/reactividad",
    name: "ssh-reactividad",
    component: SSHReactivityView,
  },
  {
    path: "/ssh/sudo",
    name: "sudo-overview",
    component: SudoOverviewView,
  },
  {
    path: "/ssh/sudo/activity",
    name: "sudo-activity",
    component: SudoActivityView,
  },
  {
    path: "/ssh/sudo-alerts",
    name: "sudo-alerts",
    component: SudoAlertsView,
  },
  {
    path: "/ssh/criticality",
    name: "security-criticality",
    component: SecurityCriticalityView,
  },
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

export default router;
