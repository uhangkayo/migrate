#!/usr/bin/env bash
#
# wp_migration_menu.sh - Unified WordPress migration menu
#
# This script consolidates export and import functionality for migrating
# WordPress sites between servers. It can be run on either the
# source (old) server or the destination (new) server. A simple menu
# allows you to export and transfer WordPress installations from the
# old server to the new server, import those packages, set up the
# database and nginx configuration, fix filesystem permissions, and
# optionally clean login banners (MOTD) that interfere with scp/ssh.
#
# Usage:
#   1. Copy this script to both old and new servers.
#   2. Run it as root. Select the export option on the old server
#      and follow the prompts to send packages to the new server.
#   3. On the new server, select the import option to extract,
#      create the database, and configure nginx.
#
# The script logs all actions with timestamps. It retries operations
# such as dumping the database and transferring files to improve
# robustness. Defaults may be overridden via environment variables
# (DEST_HOST, DEST_PORT, DEST_DIR, EXPORT_DIR, IMPORT_DIR, etc.).

set -Eeuo pipefail

# ---------------------------------------------------------------------
# Basic utility functions
# ---------------------------------------------------------------------

ts() { date '+%F %T'; }
log() { printf '[%s] %s\n' "$(ts)" "$*"; }
ok() { log "OK: $*"; }
warn() { log "WARN: $*"; }
err() { log "ERROR: $*"; }

# Catch any unhandled error and print a message
trap 'err "Unexpected error at line $LINENO"' ERR

# Print the main menu usage
show_usage() {
  cat <<'USAGE'
Menu:
  1) Export WordPress sites (run on old server)
  2) Import WordPress sites (run on new server)
  3) Clean login banner/MOTD on this machine
  4) Delete backup files and archives
  5) Full cleanup: remove all export/import data
  0) Exit
USAGE
}

# Escape single quotes in a string so it can be safely embedded in
# single‑quoted shell strings. Replaces ' with '\'' sequence.
escape_squote() {
  local s="${1:-}"
  printf '%s' "${s//\'/\'"\'"\'}"
}

# Split a host:port string into host and port components. Defaults
# port to 3306 if not specified.
split_host_port() {
  local raw="$1" host="$1" port="3306"
  if [[ "$raw" == *:* ]]; then
    host="${raw%%:*}"; port="${raw##*:}"
  fi
  printf '%s %s' "$host" "$port"
}

# ---------------------------------------------------------------------
# Login banner / MOTD cleaning
# ---------------------------------------------------------------------

# Disable pam_motd and pam_lastlog to prevent login banners from
# interfering with non‑interactive scp/ssh. Also disables update-motd.d
# scripts, sets PrintMotd to no, and ensures root .bashrc is quiet.
clean_banner() {
  log "Disabling login banners and MOTD on this machine..."
  local pam_file="/etc/pam.d/sshd"
  if [[ -f "$pam_file" ]]; then
    cp "$pam_file" "${pam_file}.bak.$(date +%s)" || true
    # Comment out pam_motd and pam_lastlog lines completely
    sed -i -E 's/^session[[:space:]]+optional[[:space:]]+pam_motd\\.so.*/# &/' "$pam_file" || true
    sed -i -E 's/^session[[:space:]]+optional[[:space:]]+pam_lastlog\\.so.*/# &/' "$pam_file" || true
  fi
  chmod -x /etc/update-motd.d/* 2>/dev/null || true
  # Disable PrintMotd
  if ! grep -q '^PrintMotd' /etc/ssh/sshd_config; then
    echo 'PrintMotd no' >> /etc/ssh/sshd_config
  else
    sed -i 's/^PrintMotd.*/PrintMotd no/' /etc/ssh/sshd_config
  fi
  # Silence .bashrc for non‑interactive sessions
  if ! grep -q 'case \$- in \*i\*\)' /root/.bashrc 2>/dev/null; then
    sed -i '1i case $- in *i*) ;; *) return;; esac' /root/.bashrc
  fi
  systemctl reload sshd 2>/dev/null || systemctl reload ssh || true
  ok "Login banners/MOTD disabled."
}

# Clean up backup files and directories. This function scans for
# leftover `.sql.gz` / `.webroot.tar.gz` archives in EXPORT_DIR and IMPORT_DIR
# as well as `.bak` directories in WEBROOT_BASE_IMPORT. It asks for confirmation
# before deleting anything. Use this after export/import operations to
# remove sensitive data.
cleanup_backups() {
  require_cmds_import || true  # ensure basic commands exist for find/ls
  log "=== Cleanup backups ==="
  local deleted_any=0
  # Clean local export backups on this machine
  if [[ -d "$EXPORT_DIR" ]]; then
    # Find .sql.gz and .webroot.tar.gz files in EXPORT_DIR
    mapfile -t __export_files < <(find "$EXPORT_DIR" -maxdepth 1 -type f \( -name '*.sql.gz' -o -name '*.webroot.tar.gz' \) 2>/dev/null)
    if (( ${#__export_files[@]} )); then
      log "File backup di $EXPORT_DIR yang ditemukan:"
      for f in "${__export_files[@]}"; do printf "  - %s\n" "$(basename "$f")"; done
      read -r -p "Hapus file backup ini dari $EXPORT_DIR? [y/N]: " ans
      if [[ "$ans" =~ ^[Yy]$ ]]; then
        rm -f "${__export_files[@]}"
        ok "Backup di $EXPORT_DIR dihapus"
        deleted_any=1
      fi
    fi
  fi
  # Clean local import backups on this machine
  if [[ -d "$IMPORT_DIR" ]]; then
    mapfile -t __import_files < <(find "$IMPORT_DIR" -maxdepth 1 -type f \( -name '*.sql.gz' -o -name '*.webroot.tar.gz' \) 2>/dev/null)
    if (( ${#__import_files[@]} )); then
      log "File backup di $IMPORT_DIR yang ditemukan:"
      for f in "${__import_files[@]}"; do printf "  - %s\n" "$(basename "$f")"; done
      read -r -p "Hapus file backup ini dari $IMPORT_DIR? [y/N]: " ans
      if [[ "$ans" =~ ^[Yy]$ ]]; then
        rm -f "${__import_files[@]}"
        ok "Backup di $IMPORT_DIR dihapus"
        deleted_any=1
      fi
    fi
  fi
  # Clean .bak directories under WEBROOT_BASE_IMPORT
  if [[ -d "$WEBROOT_BASE_IMPORT" ]]; then
    mapfile -t __bak_dirs < <(find "$WEBROOT_BASE_IMPORT" -maxdepth 2 -type d -name '*.bak' 2>/dev/null)
    if (( ${#__bak_dirs[@]} )); then
      log "Direktori backup (.bak) yang ditemukan di $WEBROOT_BASE_IMPORT:"
      for d in "${__bak_dirs[@]}"; do printf "  - %s\n" "$d"; done
      read -r -p "Hapus direktori backup ini? [y/N]: " ans
      if [[ "$ans" =~ ^[Yy]$ ]]; then
        rm -rf "${__bak_dirs[@]}"
        ok "Direktori .bak dihapus"
        deleted_any=1
      fi
    fi
  fi
  if (( deleted_any == 0 )); then
    warn "Tidak ada file atau folder backup yang dihapus."
  fi
  read -r -p "Tekan Enter untuk kembali ke menu..." _
}

# Perform a full cleanup of export/import data. This will remove all
# backup files in $EXPORT_DIR and $IMPORT_DIR as well as the export/import
# directories themselves and any .bak directories under $WEBROOT_BASE_IMPORT.
# Use this after you have completed migration to ensure no sensitive data is left.
full_cleanup_all_data() {
  require_cmds_import || true
  log "=== Full cleanup of export/import data ==="
  echo "Direktori yang akan dihapus (jika ada):"
  echo "  EXPORT_DIR: $EXPORT_DIR"
  echo "  IMPORT_DIR: $IMPORT_DIR"
  echo "  .bak directories under: $WEBROOT_BASE_IMPORT"
  read -r -p "Apakah Anda yakin ingin MENGHAPUS SEMUA data ini? [y/N]: " ans
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    # Remove export and import directories safely
    if [[ -d "$EXPORT_DIR" ]]; then
      rm -rf "$EXPORT_DIR" && ok "$EXPORT_DIR dihapus" || warn "Gagal menghapus $EXPORT_DIR"
    else
      warn "$EXPORT_DIR tidak ada, lewati."
    fi
    if [[ -d "$IMPORT_DIR" ]]; then
      rm -rf "$IMPORT_DIR" && ok "$IMPORT_DIR dihapus" || warn "Gagal menghapus $IMPORT_DIR"
    else
      warn "$IMPORT_DIR tidak ada, lewati."
    fi
    # Remove any .bak directories under WEBROOT_BASE_IMPORT
    if [[ -d "$WEBROOT_BASE_IMPORT" ]]; then
      mapfile -t bak_dirs < <(find "$WEBROOT_BASE_IMPORT" -maxdepth 2 -type d -name '*.bak' 2>/dev/null)
      if (( ${#bak_dirs[@]} )); then
        rm -rf "${bak_dirs[@]}" && ok "Direktori .bak dihapus" || warn "Gagal menghapus beberapa .bak"
      else
        warn "Tidak ada direktori .bak yang ditemukan untuk dihapus."
      fi
    fi
    ok "Full cleanup selesai."
  else
    warn "Full cleanup dibatalkan."
  fi
  read -r -p "Tekan Enter untuk kembali ke menu..." _
}

# ---------------------------------------------------------------------
# Export functions (run on old server)
# ---------------------------------------------------------------------

# Configurable defaults for export
DEST_HOST="${DEST_HOST:-}"
DEST_PORT="${DEST_PORT:-22}"
DEST_DIR="${DEST_DIR:-/root/wp_imports}"
EXPORT_DIR="${EXPORT_DIR:-/root/wp_exports}"
WEBROOT_BASE_EXPORT="${WEBROOT_BASE_EXPORT:-/var/www}"
ONLY_EXPORT="${ONLY_EXPORT:-}"
RETRY_EXPORT="${RETRY_EXPORT:-2}"

# Verify that required commands exist on the export side
require_cmds_export() {
  local cmds=(find awk sed tar gzip mysqldump scp ssh)
  local missing=()
  for c in "${cmds[@]}"; do
    command -v "$c" >/dev/null 2>&1 || missing+=("$c")
  done
  if ((${#missing[@]})); then
    err "Missing commands: ${missing[*]}"
    echo "Install them and try again." >&2
    exit 1
  fi
}

# Extract a constant from wp-config.php (define('KEY', 'value');)
parse_define() {
  local file="$1" key="$2"
  awk -v k="$key" '
    BEGIN{IGNORECASE=1}
    $0 ~ /define[[:space:]]*\(/ && $0 ~ k {
      line=$0
      while (line !~ /\);$/ && getline nxt) line=line "\n" nxt
      print line
    }
  ' "$file" 2>/dev/null | \
    sed -nE "s/.*define[[:space:]]*\([[:space:]]*['\"]${key}['\"][[:space:]]*,[[:space:]]*['\"]([^'\"]+)['\"][[:space:]]*\).*/\1/p" | \
    head -n1
}

# Fallback to WP-CLI for reading config values if parse_define fails
wp_get() {
  local key="$1" path="$2"
  if command -v wp >/dev/null 2>&1; then
    wp config get "$key" --path="$path" --allow-root 2>/dev/null || true
  else
    php -r "copy('https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar','/tmp/wp-cli.phar');" 2>/dev/null || return 1
    php /tmp/wp-cli.phar config get "$key" --path="$path" --allow-root 2>/dev/null || true
  fi
}

# Fallback to .env file
dotenv_get() {
  local key="$1" envfile="$2/.env"
  [[ -f "$envfile" ]] || return 1
  sed -nE "s/^\s*${key}\s*=\s*\"?([^\"]+)\"?\s*$/\1/p" "$envfile" | head -n1
}

# Prepare the remote directory on the destination host
ensure_dest_ready() {
  require_cmds_export
  [[ -z "$DEST_HOST" ]] && { err "DEST_HOST is not set"; return 1; }
  log "Preparing destination directory on $DEST_HOST:$DEST_DIR (port $DEST_PORT)"
  # Create destination directory non-interactively.  Using --noprofile/--norc prevents
  # MOTD/banner output from interfering with commands.  Accept unknown hosts automatically.
  ssh -q -o StrictHostKeyChecking=accept-new -p "$DEST_PORT" \
    "root@$DEST_HOST" \
    "bash --noprofile --norc -c 'mkdir -p \"${DEST_DIR}\"'" || true
}

# Discover WordPress sites to export. Populates SITES_EXPORT array.
list_sites_export() {
  SITES_EXPORT=()
  mapfile -t config_paths < <(find "$WEBROOT_BASE_EXPORT" -type f -name 'wp-config.php' 2>/dev/null | sort)
  for cfg in "${config_paths[@]}"; do
    local dir; dir="$(dirname "$cfg")"
    SITES_EXPORT+=("$dir")
  done
  if [[ -n "$ONLY_EXPORT" ]]; then
    local filtered=()
    IFS=',' read -ra want <<<"$ONLY_EXPORT"
    for path in "${SITES_EXPORT[@]}"; do
      local base; base="$(basename "$path")"
      for w in "${want[@]}"; do
        [[ "$base" == "$w" ]] && filtered+=("$path")
      done
    done
    SITES_EXPORT=("${filtered[@]}")
  fi
}

# Dump database for a site. Uses credentials from wp-config.php or
# fallback sources. Writes to $EXPORT_DIR/<site>.sql.gz
dump_db_export() {
  local site_dir="$1" site_name="$2"
  local cfg="$site_dir/wp-config.php"
  local db_name db_user db_pass db_host
  db_name="$(parse_define "$cfg" DB_NAME || true)"
  db_user="$(parse_define "$cfg" DB_USER || true)"
  db_pass="$(parse_define "$cfg" DB_PASSWORD || true)"
  db_host="$(parse_define "$cfg" DB_HOST || true)"
  [[ -z "$db_name" ]] && db_name="$(wp_get DB_NAME "$site_dir" || true)"
  [[ -z "$db_user" ]] && db_user="$(wp_get DB_USER "$site_dir" || true)"
  [[ -z "$db_pass" ]] && db_pass="$(wp_get DB_PASSWORD "$site_dir" || true)"
  [[ -z "$db_host" ]] && db_host="$(wp_get DB_HOST "$site_dir" || true)"
  [[ -z "$db_name" ]] && db_name="$(dotenv_get DB_NAME "$site_dir" || true)"
  [[ -z "$db_user" ]] && db_user="$(dotenv_get DB_USER "$site_dir" || true)"
  [[ -z "$db_pass" ]] && db_pass="$(dotenv_get DB_PASSWORD "$site_dir" || true)"
  [[ -z "$db_host" ]] && db_host="$(dotenv_get DB_HOST "$site_dir" || true)"
  # Only require DB name and DB user to be present. Allow empty DB password (some setups use no password).
  if [[ -z "$db_name" || -z "$db_user" ]]; then
    warn "[$site_name] DB credentials not found; skipping dump."
    return 1
  fi
  [[ -z "$db_host" ]] && db_host="localhost"
  read -r host port <<<"$(split_host_port "$db_host")"
  local out="$EXPORT_DIR/${site_name}.sql.gz"
  log "[$site_name] Dumping DB ($db_name@$host:$port) -> $out"
  local pw_esc; pw_esc="$(escape_squote "$db_pass")"
  local attempt=0
  while (( attempt <= RETRY_EXPORT )); do
    if [[ "$host" == "localhost" || "$host" == "127.0.0.1" ]]; then
      if eval "mysqldump --single-transaction --quick --hex-blob --default-character-set=utf8mb4 -u'$db_user' --password='$pw_esc' '$db_name' | gzip -c > '$out'"; then
        ok "[$site_name] Database dump completed"
        return 0
      fi
    else
      if eval "mysqldump --single-transaction --quick --hex-blob --default-character-set=utf8mb4 -h '$host' -P '$port' -u'$db_user' --password='$pw_esc' '$db_name' | gzip -c > '$out'"; then
        ok "[$site_name] Database dump completed"
        return 0
      fi
    fi
    # increment attempt counter safely
    attempt=$((attempt+1))
    warn "[$site_name] DB dump failed (attempt $attempt), retrying..."
    sleep 2
  done
  err "[$site_name] Failed to dump DB after $RETRY_EXPORT retries"
  return 1
}

# Create a tar.gz of the site's webroot
tar_webroot_export() {
  local site_dir="$1" site_name="$2"
  local out="$EXPORT_DIR/${site_name}.webroot.tar.gz"
  log "[$site_name] Creating webroot archive -> $out"
  local attempt=0
  while (( attempt <= RETRY_EXPORT )); do
    if tar -C "$(dirname "$site_dir")" -cf - "$(basename "$site_dir")" | gzip -c > "$out"; then
      ok "[$site_name] Webroot archive created"
      return 0
    fi
    # increment attempt counter safely
    attempt=$((attempt+1))
    warn "[$site_name] Tar failed (attempt $attempt), retrying..."
    sleep 2
  done
  err "[$site_name] Failed to tar webroot after $RETRY_EXPORT retries"
  return 1
}

# Transfer a file to the remote server. Uses scp first, then falls back
# to ssh+cat to avoid MOTD/banners if scp fails.
copy_file_export() {
  local local_file="$1" remote_file="$2"
  # Create the remote directory if it does not exist. Use non-interactive shell to avoid MOTD.
  local remote_dir
  remote_dir="$(dirname "$remote_file")"
  ssh -q -o StrictHostKeyChecking=accept-new -p "$DEST_PORT" \
    "root@$DEST_HOST" \
    "bash --noprofile --norc -c 'mkdir -p \"${remote_dir}\"'" || true
  # First try scp quietly. If it fails, fall back to ssh+cat which avoids MOTD/banner issues.
  if scp -q -P "$DEST_PORT" "$local_file" "root@$DEST_HOST:$remote_file" >/dev/null 2>&1; then
    return 0
  fi
  if ssh -q -p "$DEST_PORT" "root@$DEST_HOST" \
      "bash --noprofile --norc -c 'cat > \"${remote_file}\"'" < "$local_file"; then
    return 0
  fi
  return 1
}

# Transfer both DB dump and webroot archive for a site
transfer_site_export() {
  local site_name="$1"
  local sql="$EXPORT_DIR/${site_name}.sql.gz"
  local tar="$EXPORT_DIR/${site_name}.webroot.tar.gz"
  if [[ -f "$sql" ]]; then
    log "[$site_name] Transferring SQL dump to $DEST_HOST:$DEST_DIR"
    local attempt=0
    while (( attempt <= RETRY_EXPORT )); do
      if copy_file_export "$sql" "$DEST_DIR/$(basename "$sql")"; then
        ok "[$site_name] SQL transferred"
        break
      fi
        # increment attempt counter safely
        attempt=$((attempt+1))
      warn "[$site_name] SQL transfer failed (attempt $attempt), retrying..."
      sleep 2
    done
  else
    warn "[$site_name] SQL dump missing, skipping SQL transfer"
  fi
  if [[ -f "$tar" ]]; then
    log "[$site_name] Transferring webroot archive to $DEST_HOST:$DEST_DIR"
    local attempt=0
    while (( attempt <= RETRY_EXPORT )); do
      if copy_file_export "$tar" "$DEST_DIR/$(basename "$tar")"; then
        ok "[$site_name] Webroot transferred"
        break
      fi
      # increment attempt counter safely
      attempt=$((attempt+1))
      warn "[$site_name] Webroot transfer failed (attempt $attempt), retrying..."
      sleep 2
    done
  else
    warn "[$site_name] Webroot archive missing, skipping webroot transfer"
  fi
}

# Interactive menu for export operations
menu_export() {
  require_cmds_export
  # Prompt for destination host if not preset
  if [[ -z "$DEST_HOST" ]]; then
    read -r -p "Masukkan IP/hostname server baru: " DEST_HOST
    if [[ -z "$DEST_HOST" ]]; then
      err "Destination host must be provided."; return
    fi
  fi
  # Port
  read -r -p "Masukkan port SSH server baru [$DEST_PORT]: " tmp_port
  DEST_PORT="${tmp_port:-$DEST_PORT}"
  # Directory
  read -r -p "Masukkan folder tujuan di server baru [$DEST_DIR]: " tmp_dir
  DEST_DIR="${tmp_dir:-$DEST_DIR}"
  # List sites
  list_sites_export
  local count=${#SITES_EXPORT[@]}
  if (( count == 0 )); then
    err "Tidak ditemukan wp-config.php di $WEBROOT_BASE_EXPORT"
    return
  fi
  log "Ditemukan $count WordPress site:"
  # display numbered list of exportable sites
  local i=0
  for path in "${SITES_EXPORT[@]}"; do
    # increment i explicitly rather than relying on ((i++)) which may return non-zero
    i=$((i+1))
    printf "  %2d) %s (%s)\n" "$i" "$(basename "$path")" "$path"
  done
  echo
  read -r -p "Masukkan nomor site (pisah koma) atau ALL [ALL]: " pick
  pick="${pick:-ALL}"
  local selections=()
  if [[ "$pick" =~ ^([Aa][Ll][Ll])$ ]]; then
    for ((j=1; j<=count; j++)); do selections+=("$j"); done
  else
    IFS=',' read -ra selections <<<"$pick"
  fi
  mkdir -p "$EXPORT_DIR"
  ensure_dest_ready
  for sel in "${selections[@]}"; do
    if ! [[ "$sel" =~ ^[0-9]+$ ]] || (( sel < 1 || sel > count )); then
      warn "Nomor tidak valid: $sel"; continue
    fi
    local dir="${SITES_EXPORT[$((sel-1))]}"
    local name; name="$(basename "$dir")"
    log "--- Menangani [$name] ---"
    dump_db_export "$dir" "$name" || warn "[$name] DB dump error"
    tar_webroot_export "$dir" "$name" || warn "[$name] Tar error"
    transfer_site_export "$name" || warn "[$name] Transfer error"
    ok "[$name] Ekspor selesai"
  done
  ok "Ekspor selesai. File lokal di $EXPORT_DIR; file remote di $DEST_HOST:$DEST_DIR"
}

# ---------------------------------------------------------------------
# Import functions (run on new server)
# ---------------------------------------------------------------------

# Import defaults
IMPORT_DIR="${IMPORT_DIR:-/root/wp_imports}"
WEBROOT_BASE_IMPORT="${WEBROOT_BASE_IMPORT:-/var/www}"
NGINX_AVAIL="${NGINX_AVAIL:-/etc/nginx/sites-available}"
NGINX_ENABLED="${NGINX_ENABLED:-/etc/nginx/sites-enabled}"
DEFAULT_PHP_VERSION="${DEFAULT_PHP_VERSION:-}"
SERVER_IP_HINT="${SERVER_IP_HINT:-}"

# Ensure required commands on import side
require_cmds_import() {
  local cmds=(tar gzip awk sed grep ln systemctl)
  local missing=()
  for c in "${cmds[@]}"; do
    command -v "$c" >/dev/null 2>&1 || missing+=("$c")
  done
  if ((${#missing[@]})); then
    err "Missing commands: ${missing[*]}"
    echo "Install them first." >&2
    exit 1
  fi
  command -v nginx >/dev/null 2>&1 || warn "nginx not found in PATH"
  command -v mysql >/dev/null 2>&1 || warn "mysql not found in PATH"
}

# Detect PHP-FPM socket; return empty if not found
detect_php_fpm_socket() {
  if [[ -n "$DEFAULT_PHP_VERSION" ]]; then
    local sock="/run/php/php${DEFAULT_PHP_VERSION}-fpm.sock"
    [[ -S "$sock" ]] && { echo "$sock"; return; }
  fi
  local cand
  cand="$(ls -1 /run/php/php*-fpm.sock 2>/dev/null | sort -Vr | head -n1 || true)"
  [[ -S "$cand" ]] && echo "$cand" || echo ""
}

# Ask the user (or auto-detect) for the PHP-FPM version
prompt_php_version_if_needed() {
  # Determine the PHP-FPM version to use for nginx fastcgi_pass
  # First try auto-detecting an existing php*-fpm socket. If that fails, use
  # DEFAULT_PHP_VERSION if set, otherwise fall back to 8.3.  We avoid
  # prompting the user inside automated import routines.
  local sock
  sock="$(detect_php_fpm_socket || true)"
  if [[ -z "$sock" ]]; then
    # If the caller has set DEFAULT_PHP_VERSION, try that
    local fallback="${DEFAULT_PHP_VERSION:-}"
    # If no fallback yet, default to 8.3
    [[ -z "$fallback" ]] && fallback="8.3"
    sock="/run/php/php${fallback}-fpm.sock"
    if [[ ! -S "$sock" ]]; then
      warn "Tidak dapat menemukan socket PHP-FPM otomatis; mencoba fallback php${fallback}-fpm.sock yang tidak ada."
      # leave DEFAULT_PHP_VERSION blank so downstream can handle missing fastcgi
      DEFAULT_PHP_VERSION="$fallback"
    else
      DEFAULT_PHP_VERSION="$fallback"
    fi
  else
    # Parse version from socket filename (supports php8.3-fpm.sock and php8.3-fpm.sock variants)
    local base
    base="$(basename "$sock")"
    DEFAULT_PHP_VERSION="$(printf '%s' "$base" | sed -nE 's/^php([0-9]+\.[0-9]+)-fpm\.sock$/\1/p')"
    # Fallback: if pattern didn't match, strip prefix/suffix crudely
    [[ -z "$DEFAULT_PHP_VERSION" ]] && DEFAULT_PHP_VERSION="$(printf '%s' "$base" | sed -nE 's/^php(.*)-fpm\.sock$/\1/p')"
  fi
  ok "PHP-FPM versi digunakan: ${DEFAULT_PHP_VERSION:-<none>}"
}

# MySQL root login
MYSQL_ROOT_ARGS=()
check_mysql_root() {
  # Try without password first
  if mysql -uroot -e "SELECT 1" >/dev/null 2>&1; then
    MYSQL_ROOT_ARGS=(-uroot)
    return
  fi
  read -r -s -p "Masukkan password MySQL root: " mpass; echo
  MYSQL_ROOT_ARGS=(-uroot "-p${mpass}")
  if ! mysql "${MYSQL_ROOT_ARGS[@]}" -e "SELECT 1" >/dev/null 2>&1; then
    err "Login MySQL root gagal"
    exit 1
  fi
}

mysql_exec() { mysql "${MYSQL_ROOT_ARGS[@]}" -e "$1"; }

ensure_db_and_user() {
  local db="$1" user="$2" pass="$3"
  mysql_exec "CREATE DATABASE IF NOT EXISTS \`$db\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
  mysql_exec "CREATE USER IF NOT EXISTS '$user'@'localhost' IDENTIFIED BY '$pass';"
  mysql_exec "ALTER USER '$user'@'localhost' IDENTIFIED BY '$pass';"
  mysql_exec "GRANT ALL PRIVILEGES ON \`$db\`.* TO '$user'@'localhost'; FLUSH PRIVILEGES;"
  ok "Database dan user disiapkan: $db / $user"
}

import_sql_gz() {
  local db="$1" file="$2"
  if [[ ! -f "$file" ]]; then warn "File SQL tidak ditemukan: $file"; return 1; fi
  log "Impor SQL ke DB $db dari file $(basename "$file")"
  if ! gzip -dc "$file" | mysql "${MYSQL_ROOT_ARGS[@]}" "$db"; then
    err "Impor SQL gagal: $file"
    return 1
  fi
  ok "Impor SQL selesai"
}

# Create nginx server block
gen_nginx_server_block() {
  local site="$1" root="$2" php_ver="$3"
  # Sanitize the site name for filesystem usage: replace any unsafe char with '_'.
  local sanitized
  sanitized=$(printf '%s' "$site" | sed 's/[^A-Za-z0-9._-]/_/g')
  local conf="$NGINX_AVAIL/$sanitized"
  local sock="/run/php/php${php_ver}-fpm.sock"
  # Remove any existing symlink with the original site name to avoid stale/broken configs
  rm -f "$NGINX_ENABLED/$site" 2>/dev/null || true
  # Generate nginx server block
  cat > "$conf" <<NGX
server {
    listen 80;
    server_name ${site};
    root ${root};
    index index.php index.html;

    client_max_body_size 64m;

    location / {
        try_files \$uri \$uri/ /index.php?\$args;
    }

    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:${sock};
    }

    location ~* \.(jpg|jpeg|png|gif|svg|webp|ico|css|js|woff2?|ttf)\$ {
        expires 7d;
        access_log off;
        try_files \$uri =404;
    }
}
NGX
  # Symlink into sites-enabled using sanitized filename
  ln -sf "$conf" "$NGINX_ENABLED/$sanitized"
  if nginx -t; then
    systemctl reload nginx || true
    ok "Nginx block dibuat dan reload: $site"
  else
    err "nginx -t gagal untuk $site"
    return 1
  fi
}

# Fix file ownership and permissions
fix_permissions() {
  local path="$1"
  chown -R www-data:www-data "$path"
  find "$path" -type d -exec chmod 755 {} \;
  find "$path" -type f -exec chmod 644 {} \;
  ok "Permissions diperbaiki: $path"
}

# List import packages (sites)
list_packages() {
  # Safely list available import packages. If the directory doesn't exist, return nothing.
  if [[ ! -d "$IMPORT_DIR" ]]; then
    return 0
  fi
  # Use find instead of ls so that no-match patterns do not cause the pipeline to fail under set -e/pipefail
  find "$IMPORT_DIR" -maxdepth 1 -type f -name '*.webroot.tar.gz' -printf '%f\n' 2>/dev/null \
    | sed -nE 's/^(.*)\.webroot\.tar\.gz$/\1/p' | sort -u
}

has_sql() { [[ -f "${IMPORT_DIR}/$1.sql.gz" ]]; }
has_tar() { [[ -f "${IMPORT_DIR}/$1.webroot.tar.gz" ]]; }

# Process one site during import
process_site_import() {
  local site="$1"
  local tarf="${IMPORT_DIR}/${site}.webroot.tar.gz"
  local sqlf="${IMPORT_DIR}/${site}.sql.gz"
  local dst="${WEBROOT_BASE_IMPORT}/${site}"
  log "=== Import ${site} ==="
  # Extract webroot
  if [[ -d "$dst" ]]; then
    local backup="${dst}.$(date +%Y%m%d%H%M%S).bak"
    warn "Folder $dst sudah ada; backup ke $backup"
    mv "$dst" "$backup"
  fi
  mkdir -p "$WEBROOT_BASE_IMPORT"
  log "[${site}] Ekstrak webroot -> $dst"
  tar -C "$WEBROOT_BASE_IMPORT" -xzf "$tarf"
  ok "[${site}] Ekstrak webroot selesai"
  # Parse credentials from wp-config.php
  local cfg="$dst/wp-config.php"
  local db_name db_user db_pass db_host
  db_name="$(parse_define "$cfg" DB_NAME || true)"
  db_user="$(parse_define "$cfg" DB_USER || true)"
  db_pass="$(parse_define "$cfg" DB_PASSWORD || true)"
  db_host="$(parse_define "$cfg" DB_HOST || true)"
  # Require DB_NAME and DB_USER to be present. Allow empty DB_PASSWORD (can be empty string).
  if [[ -z "$db_name" || -z "$db_user" ]]; then
    warn "[${site}] Kredensial tidak lengkap di wp-config.php"
    read -r -p "Masukkan DB_NAME untuk ${site}: " db_name
    read -r -p "Masukkan DB_USER untuk ${site}: " db_user
    read -r -s -p "Masukkan DB_PASSWORD untuk ${site} (biarkan kosong jika tidak ada): " db_pass; echo
    db_host="${db_host:-localhost}"
    # Write credentials back into wp-config.php. Always write password define even if empty.
    sed -i "s/define\\s*(\'?DB_NAME'\\?,\\s*'.*');/define( 'DB_NAME', '${db_name}' );/I" "$cfg" || true
    sed -i "s/define\\s*(\'?DB_USER'\\?,\\s*'.*');/define( 'DB_USER', '${db_user}' );/I" "$cfg" || true
    sed -i "s/define\\s*(\'?DB_PASSWORD'\\?,\\s*'.*');/define( 'DB_PASSWORD', '${db_pass}' );/I" "$cfg" || true
    if [[ -n "$db_host" ]]; then
      sed -i "s/define\\s*(\'?DB_HOST'\\?,\\s*'.*');/define( 'DB_HOST', '${db_host}' );/I" "$cfg" || true
    fi
    ok "[${site}] wp-config.php updated with new credentials"
  fi
  db_host="${db_host:-localhost}"
  # Prepare DB
  check_mysql_root
  ensure_db_and_user "$db_name" "$db_user" "$db_pass"
  # Import SQL
  if [[ -f "$sqlf" ]]; then
    import_sql_gz "$db_name" "$sqlf" || warn "[${site}] Gagal impor SQL"
  else
    warn "[${site}] File SQL tidak ditemukan; lewati impor DB"
  fi
  # Fix permissions
  fix_permissions "$dst"
  # Nginx
  prompt_php_version_if_needed
  # Generate nginx server block; if it fails, log a warning instead of exiting
  if ! gen_nginx_server_block "$site" "$dst" "$DEFAULT_PHP_VERSION"; then
    warn "[${site}] Gagal membuat nginx block, periksa konfigurasi secara manual"
  fi
  log "--- Selesai import ${site} ---"
  [[ -n "$SERVER_IP_HINT" ]] && echo "Atur DNS ${site} -> ${SERVER_IP_HINT}"
  echo
}

# Import a site in replace mode: only replace the files and database of an existing site on the destination server.
# This function will:
#   * Read database credentials from the existing site's wp-config.php
#   * Backup the current webroot and extract the imported package
#   * Update the imported wp-config.php to use the original database credentials
#   * Ensure the database and user exist, then import the SQL dump
#   * Fix filesystem permissions
#   * Skip generating nginx configuration

process_site_replace_import() {
  local site="$1"
  local tarf="${IMPORT_DIR}/${site}.webroot.tar.gz"
  local sqlf="${IMPORT_DIR}/${site}.sql.gz"
  local dst="${WEBROOT_BASE_IMPORT}/${site}"
  log "=== Replace import ${site} ==="
  # Pastikan direktori target sudah ada (situs harus terpasang terlebih dahulu)
  if [[ ! -d "$dst" ]]; then
    err "Direktori situs belum ada: $dst. Buat terlebih dahulu sebelum replace."
    return 1
  fi
  # Backup existing webroot
  local backup="${dst}.$(date +%Y%m%d%H%M%S).bak"
  warn "[$site] Direktori ada; backup ke $backup"
  mv "$dst" "$backup"
  # Extract new webroot
  mkdir -p "$WEBROOT_BASE_IMPORT"
  log "[$site] Ekstrak webroot -> $dst"
  tar -C "$WEBROOT_BASE_IMPORT" -xzf "$tarf"
  ok "[$site] Ekstrak webroot selesai"
  # Parse credentials from imported wp-config.php
  local new_cfg="$dst/wp-config.php"
  local db_name="" db_user="" db_pass="" db_host=""
  if [[ -f "$new_cfg" ]]; then
    db_name="$(parse_define "$new_cfg" DB_NAME || true)"
    db_user="$(parse_define "$new_cfg" DB_USER || true)"
    db_pass="$(parse_define "$new_cfg" DB_PASSWORD || true)"
    db_host="$(parse_define "$new_cfg" DB_HOST || true)"
  fi
  # If DB_NAME or DB_USER missing, prompt for credentials and update wp-config.php
  if [[ -z "$db_name" || -z "$db_user" ]]; then
    warn "[$site] Kredensial DB tidak lengkap di wp-config.php hasil import"
    read -r -p "Masukkan DB_NAME untuk ${site}: " db_name
    read -r -p "Masukkan DB_USER untuk ${site}: " db_user
    read -r -s -p "Masukkan DB_PASSWORD untuk ${site} (biarkan kosong jika tidak ada): " db_pass; echo
    read -r -p "Masukkan DB_HOST untuk ${site} [localhost]: " db_host_in
    db_host="${db_host_in:-localhost}"
    # Tulis ulang definisi ke wp-config.php
    # Always write DB_NAME and DB_USER; write DB_PASSWORD and DB_HOST even if empty
    sed -i "s/define\s*(\'?DB_NAME\'?\s*,\s*'.*');/define( 'DB_NAME', '${db_name}' );/I" "$new_cfg" || true
    sed -i "s/define\s*(\'?DB_USER\'?\s*,\s*'.*');/define( 'DB_USER', '${db_user}' );/I" "$new_cfg" || true
    # For DB_PASSWORD, handle empty password by writing empty string
    local pw_repl="define( 'DB_PASSWORD', '${db_pass}' );"
    sed -i "s/define\s*(\'?DB_PASSWORD\'?\s*,\s*'.*');/${pw_repl}/I" "$new_cfg" || true
    if [[ -n "$db_host" ]]; then
      sed -i "s/define\s*(\'?DB_HOST\'?\s*,\s*'.*');/define( 'DB_HOST', '${db_host}' );/I" "$new_cfg" || true
    fi
    ok "[$site] wp-config.php diperbarui dengan kredensial baru"
  fi
  # Default DB host jika masih kosong
  [[ -z "$db_host" ]] && db_host="localhost"
  # Buat database dan user di server baru sesuai kredensial import
  check_mysql_root
  ensure_db_and_user "$db_name" "$db_user" "$db_pass"
  # Import SQL dump jika tersedia
  if [[ -f "$sqlf" ]]; then
    import_sql_gz "$db_name" "$sqlf" || warn "[$site] Gagal impor SQL"
  else
    warn "[$site] File SQL tidak ditemukan; lewati impor DB"
  fi
  # Perbaiki permission
  fix_permissions "$dst"
  log "--- Selesai replace import ${site} ---"
}

# Interactive menu for import operations
menu_import() {
  require_cmds_import
  while true; do
    clear
    echo "------------------- MENU IMPOR -------------------"
    echo "Directory paket : $IMPORT_DIR"
    echo "Root web        : $WEBROOT_BASE_IMPORT"
    echo "PHP-FPM version : ${DEFAULT_PHP_VERSION:-auto}"
    [[ -n "$SERVER_IP_HINT" ]] && echo "IP hint         : $SERVER_IP_HINT"
    echo "--------------------------------------------------"
    echo "1) Daftar paket"
    echo "2) Import situs"
    echo "3) Regenerate nginx"
    echo "4) Perbaiki permissions"
    echo "5) Bersihkan banner/MOTD"
    echo "0) Kembali"
    read -r -p "Pilih [0-5]: " ans
    case "$ans" in
      1)
        log "Paket yang tersedia:"
        local any=0
        while IFS= read -r s; do
          any=1
          local flags=""
          has_tar "$s" && flags="WEBROOT"
          has_sql "$s" && flags="${flags}${flags:++}SQL"
          printf "  - %-30s [%s]\n" "$s" "$flags"
        done < <(list_packages)
        [[ $any -eq 0 ]] && warn "Tidak ada paket."
        read -r -p "Enter untuk kembali..." _;;
      2)
        local sites=(); while IFS= read -r s; do sites+=("$s"); done < <(list_packages)
        local total=${#sites[@]}
        if (( total == 0 )); then warn "Tidak ada paket."; read -r -p "Enter..." _; continue; fi
        log "Pilih situs untuk import:"
        local i=1; for s in "${sites[@]}"; do printf "  %2d) %s\n" "$i" "$s"; i=$((i+1)); done
        read -r -p "Masukkan nomor (pisah koma) atau ALL [ALL]: " pick
        pick="${pick:-ALL}"
        local sel_idxs=()
        if [[ "$pick" =~ ^([Aa][Ll][Ll])$ ]]; then
          for ((j=1;j<=total;j++)); do sel_idxs+=("$j"); done
        else
          IFS=',' read -ra sel_idxs <<<"$pick"
        fi
        # Ask whether to replace existing sites (skip nginx/php/ssl config) or perform full import
        local replace_choice
        read -r -p "Gunakan mode replace (hanya ganti data & file, tanpa konfigurasi)? [y/N]: " replace_choice
        replace_choice="${replace_choice:-N}"
        for idx_sel in "${sel_idxs[@]}"; do
          if ! [[ "$idx_sel" =~ ^[0-9]+$ ]] || (( idx_sel < 1 || idx_sel > total )); then
            warn "Nomor tidak valid: $idx_sel"; continue
          fi
          local site_name="${sites[$((idx_sel-1))]}"
          if [[ "$replace_choice" =~ ^[Yy]$ ]]; then
            process_site_replace_import "$site_name" || warn "Replace import bermasalah untuk $site_name"
          else
            process_site_import "$site_name" || warn "Import bermasalah untuk $site_name"
          fi
        done
        read -r -p "Selesai import. Enter untuk kembali..." _;;
      3)
        # regenerate nginx
        prompt_php_version_if_needed
        local sites=(); while IFS= read -r s; do sites+=("$s"); done < <(list_packages)
        local total=${#sites[@]}
        if (( total == 0 )); then warn "Tidak ada paket."; read -r -p "Enter..." _; continue; fi
        log "Pilih situs untuk regenerate nginx:"
        local i=1; for s in "${sites[@]}"; do printf "  %2d) %s\n" "$i" "$s"; i=$((i+1)); done
        read -r -p "Masukkan nomor (pisah koma) atau ALL [ALL]: " pick
        pick="${pick:-ALL}"
        local sel_idxs=()
        if [[ "$pick" =~ ^([Aa][Ll][Ll])$ ]]; then
          for ((j=1;j<=total;j++)); do sel_idxs+=("$j"); done
        else
          IFS=',' read -ra sel_idxs <<<"$pick"
        fi
        for idx_sel in "${sel_idxs[@]}"; do
          if ! [[ "$idx_sel" =~ ^[0-9]+$ ]] || (( idx_sel < 1 || idx_sel > total )); then
            warn "Nomor tidak valid: $idx_sel"; continue
          fi
          local site="${sites[$((idx_sel-1))]}"
          gen_nginx_server_block "$site" "$WEBROOT_BASE_IMPORT/$site" "$DEFAULT_PHP_VERSION" || warn "Regenerate gagal: $site"
        done
        read -r -p "Regenerate selesai. Enter untuk kembali..." _;;
      4)
        local sites=(); while IFS= read -r s; do sites+=("$s"); done < <(list_packages)
        local total=${#sites[@]}
        if (( total == 0 )); then warn "Tidak ada paket."; read -r -p "Enter..." _; continue; fi
        log "Pilih situs untuk perbaiki permissions:"
        local i=1; for s in "${sites[@]}"; do printf "  %2d) %s\n" "$i" "$s"; i=$((i+1)); done
        read -r -p "Masukkan nomor (pisah koma) atau ALL [ALL]: " pick
        pick="${pick:-ALL}"
        local sel_idxs=()
        if [[ "$pick" =~ ^([Aa][Ll][Ll])$ ]]; then
          for ((j=1;j<=total;j++)); do sel_idxs+=("$j"); done
        else
          IFS=',' read -ra sel_idxs <<<"$pick"
        fi
        for idx_sel in "${sel_idxs[@]}"; do
          if ! [[ "$idx_sel" =~ ^[0-9]+$ ]] || (( idx_sel < 1 || idx_sel > total )); then
            warn "Nomor tidak valid: $idx_sel"; continue
          fi
          fix_permissions "$WEBROOT_BASE_IMPORT/${sites[$((idx_sel-1))]}"
        done
        read -r -p "Permissions selesai. Enter untuk kembali..." _;;
      5)
        clean_banner
        read -r -p "Banner dibersihkan. Enter untuk kembali..." _;;
      0)
        break;;
      *) warn "Pilihan tidak dikenal"; sleep 1;;
    esac
  done
}

# ---------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------

while true; do
  echo
  echo "============== WORDPRESS MIGRATION MENU =============="
  show_usage
  read -r -p "Pilih opsi [0-5]: " choice
  case "$choice" in
    1) menu_export ;;
    2) menu_import ;;
    3) clean_banner ;;
    4) cleanup_backups ;;
    5) full_cleanup_all_data ;;
    0) echo "Keluar."; exit 0 ;;
    *) warn "Pilihan tidak dikenal. Coba lagi." ;;
  esac
done
