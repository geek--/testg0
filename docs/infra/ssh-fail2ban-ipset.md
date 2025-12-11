# Reglas de baneo SSH con Fail2ban + ipset (isov3)

Este documento define la configuración inicial para endurecer el acceso SSH en el servidor **isov3** usando Fail2ban respaldado por **ipset**. El alcance se limita al módulo de SSH; la integración con Nginx/ModSecurity u otros servicios quedará para un módulo posterior. Una vez habilitado, podremos consumir los eventos de baneo desde la bitácora de Fail2ban para alimentar el futuro Tab **"Reactividad"**.

## Prerrequisitos
- Paquetes: `fail2ban`, `ipset` y el backend de firewall que ya utilice el host (iptables/nftables).  
- Registro de autenticación SSH en `/var/log/auth.log` o `/var/log/secure` según la distribución.
- Usuario con privilegios de `sudo` para aplicar las reglas.

## 1. Conjunto ipset persistente
1. Crear un set para los bloqueos SSH y hacerlo persistente (la ruta de `ipset` en isov3 es `/usr/sbin/ipset`):
   ```bash
   sudo /usr/sbin/ipset create ssh-banned hash:ip -exist
   sudo mkdir -p /etc/ipset.d
   sudo sh -c '/usr/sbin/ipset save ssh-banned > /etc/ipset.d/ssh-banned.conf'
   ```
2. Asegurar restauración en el arranque (systemd):
   ```ini
   # /etc/systemd/system/ipset-ssh.service
   [Unit]
   Description=Restore ssh-banned ipset
   Wants=network-pre.target
   Before=network-pre.target

   [Service]
   Type=oneshot
   ExecStart=/bin/sh -c '/usr/sbin/ipset restore < /etc/ipset.d/ssh-banned.conf'
   ExecReload=/bin/sh -c '/usr/sbin/ipset restore < /etc/ipset.d/ssh-banned.conf'
   RemainAfterExit=yes

   [Install]
   WantedBy=multi-user.target
   ```
   Activar con `sudo systemctl enable --now ipset-ssh.service`.

## 2. Acción Fail2ban para ipset
Crear una acción específica que inserte y quite IPs del set `ssh-banned`:
```ini
# /etc/fail2ban/action.d/ipset-ssh-ban.conf
[Definition]
actionstart = /usr/sbin/ipset create ssh-banned hash:ip -exist
actionstop  = /usr/sbin/ipset flush ssh-banned
actioncheck = /usr/sbin/ipset list ssh-banned

# Solo Fail2ban controla los tiempos: el set no lleva timeout y se añade tal cual
actionban   = /usr/sbin/ipset add ssh-banned <ip> -exist

# Elimina la IP cuando expire/sea desbaneada
actionunban = /usr/sbin/ipset del ssh-banned <ip>

[Init]
# Usar el bantime efectivo de la jail
bantime = %(bantime)s
```
> Nota: `actionstop` vacía el set si se reinicia o detiene Fail2ban. Si quisieras conservar los baneos a través de reinicios de
> Fail2ban, comenta esa línea.

## 3. Jail dedicada a SSH
Habilitar una jail que use la acción anterior. Ajusta los valores según la política interna.
```ini
# /etc/fail2ban/jail.d/ssh-ipset.local
[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
backend  = systemd
maxretry = 4
findtime = 10m
bantime  = 12h
action   = ipset-ssh-ban[name=sshd]
```
Si la distribución usa `/var/log/secure`, cambia `logpath` en consecuencia.

## 4. Pruebas y operación
- Recargar Fail2ban tras crear la acción y la jail: `sudo systemctl restart fail2ban`.
- Verificar que la jail está activa y que usa ipset: `sudo fail2ban-client status sshd`.
- Consultar las IP baneadas: `sudo ipset list ssh-banned`.
- Desbanear manualmente (si es necesario): `sudo fail2ban-client set sshd unbanip <IP>`.

### Integración con UFW para aplicar el set
UFW no carga snippets en `before.rules.d`. Añade la regla directamente en `/etc/ufw/before.rules`, antes de la cadena
`ufw-before-input`, para que el set se aplique lo antes posible:
1. Haz copia de seguridad: `sudo cp /etc/ufw/before.rules /etc/ufw/before.rules.bak`.
2. Edita `/etc/ufw/before.rules` y, dentro del bloque `*filter`, declara la cadena y el salto. El inicio debería verse así
   (mantén el resto de reglas tal cual están tras estas líneas):
   ```
   *filter
   :ufw-ssh-banned - [0:0]
   -A ufw-ssh-banned -m set --match-set ssh-banned src -j DROP

   # Aplicar la lista ssh-banned lo antes posible
   -A ufw-before-input -j ufw-ssh-banned
   ...
   ```
3. Recarga UFW: `sudo ufw reload`.

## 5. Consideraciones para "Reactividad"
- Fail2ban registra cada baneo/desbaneo en `/var/log/fail2ban.log`; ese archivo será la fuente recomendada para consumir eventos en la futura API/Tab "Reactividad".
- Si más adelante se desea incluir Nginx/ModSecurity, se puede agregar otra jail apuntando al log de ModSecurity (`/var/log/modsec_audit.log`) y reutilizar la misma acción `ipset-ssh-ban` para unificar los sets bloqueados.
- Mantener separados los sets (`ssh-banned`, `http-banned`, etc.) facilitará mostrar estadísticas por módulo en la UI.
