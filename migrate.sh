#!/usr/bin/env bash
# migration_menu_v1.sh — Menu-based Pull Migration for WordPress Subdomain
# TARGET (server baru) menarik data dari SOURCE (server lama)
# Fitur:
#  - Menu interaktif: profil, konektivitas, auto-detect webroot & DB, migrasi file, import DB,
#    tulis Nginx, finalize (ownership & reload).
#  - Simpan/Load profil di /etc/server_manager/migration.d/<subdomain>.conf
#  - SSH key atau password (sshpass)
#  - Anti-banner: sentinel __BEGIN__/__END__ untuk bersihkan output remote
#  - rsync opsi-kompatibel otomatis; fallback tar stream
#  - Logging: /var/log/migration_menu_<timestamp>.log

set -euo pipefail
IFS=$'\n\t'

# ====== Global ======
TS="$(date +%Y%m%d-%H%M%S)"
LOG_FILE="/var/log/migration_menu_${TS}.log"
PROFILE_DIR="/etc/server_manager/migration.d"
mkdir -p "$PROFILE_DIR" >/dev/null 2>&1 || true

# runtime vars (diisi via menu/atau load profil)
SUBDOMAIN=""
SRC_HOST=""
SRC_USER="root"
SRC_PORT="22"
SSHPASS=""

SRC_WEBROOT=""               # auto detect jika kosong
DST_WEBROOT=""               # default: /var/www/<subdomain>

WANT_DB="auto"               # auto/yes/no
DB_NAME=""
DB_USER=""
DB_PASS=""
T_DB=""
T_USER=""
T_PASS=""

NO_NGINX="0"                 # 1=skip tulis nginx
DRY_RUN="0"                  # 1=rsync dry-run
FORCE_RSYNC="1"              # 1=rsync, 0=tar

SSH_LAST_STATUS=0
SSH_LAST_ERROR=""
SSHPASS_WARNED="0"
SSHPASS_FALLBACK="0"
SSH_BASE_CMD=""

# ====== Helpers ======
log()   { printf "[%s] %s\n" "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE"; }
warn()  { printf "\033[33mWARN:\033[0m %s\n" "$*" | tee -a "$LOG_FILE"; }
err()   { printf "\033[31mERROR:\033[0m %s\n" "$*" | tee -a "$LOG_FILE"; }
need()  { command -v "$1" >/dev/null 2>&1 || { err "Missing '$1'"; return 1; } }
bytes_to_h(){ awk -v b="${1:-0}" 'function H(x){s[0]="B";s[1]="K";s[2]="M";s[3]="G";s[4]="T";i=0;while(x>=1024&&i<4){x/=1024;i++}return sprintf("%.2f%s",x,s[i])}BEGIN{print H(b)}'; }
sanitize(){ echo "$1" | tr -cd '[:alnum:]_.-'; }
pause(){ read -r -p "Press Enter untuk lanjut... " _ || true; }

phpfpm_sock_guess(){
  for v in 8.4 8.3 8.2 8.1 8.0 7.4; do s="/run/php/php${v}-fpm.sock"; [[ -S "$s" ]] && { echo "$s"; return; }; done
  [[ -S /run/php/php-fpm.sock ]] && { echo /run/php/php-fpm.sock; return; }
  [[ -S /var/run/php/php-fpm.sock ]] && { echo /var/run/php/php-fpm.sock; return; }
  echo /run/php/php-fpm.sock
}

notify(){ command -v notify-send >/dev/null 2>&1 && notify-send "Migration Menu" "$*" || true; log "$*"; }

# ====== SSH wrappers (sentinel) ======
build_ssh_base(){
  SSHPASS_FALLBACK="0"
  SSH_BASE_CMD=""
  if [[ -n "$SSHPASS" ]]; then
    if command -v sshpass >/dev/null 2>&1; then
      printf -v SSH_BASE_CMD "sshpass -p '%s' ssh -T -q -p %s -o LogLevel=ERROR -o StrictHostKeyChecking=accept-new -o SetEnv=TERM=dumb %s@%s" \
        "$(printf "%s" "$SSHPASS")" "$SRC_PORT" "$SRC_USER" "$SRC_HOST"
      return 0
    fi
    SSHPASS_FALLBACK="1"
  fi
  printf -v SSH_BASE_CMD "ssh -T -q -p %s -o LogLevel=ERROR -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o SetEnv=TERM=dumb %s@%s" \
    "$SRC_PORT" "$SRC_USER" "$SRC_HOST"
  return 0
}

remote_marked(){
  local cmd="$1"
  build_ssh_base
  local ssh_cmd="$SSH_BASE_CMD"
  # shellcheck disable=SC2016
  eval "TERM=dumb $ssh_cmd 'printf __BEGIN__; ( $cmd ) 2>/dev/null; printf __END__' " \
    2> >(grep -v 'TERM environment variable not set' >&2) \
    | sed -n '/__BEGIN__/,/__END__/p' | sed -e '1d' -e '$d'
}

ssh_check(){
  local ssh_cmd tmp_err raw status filtered
  build_ssh_base
  ssh_cmd="$SSH_BASE_CMD"
  tmp_err="$(mktemp)"
  raw=$(eval "TERM=dumb $ssh_cmd 'printf __BEGIN__; echo ok; printf __END__' " \
    2> >(grep -v 'TERM environment variable not set' | tee "$tmp_err" >&2))
  status=$?
  filtered="$(sed 's/\r$//' "$tmp_err" | sed '/^[[:space:]]*$/d' | tail -n1)"
  rm -f "$tmp_err"

  if [[ $status -ne 0 ]]; then
    SSH_LAST_STATUS=$status
    SSH_LAST_ERROR="$filtered"
    return 1
  fi

  raw=$(printf '%s\n' "$raw" | sed -n 's/^.*__BEGIN__\(.*\)__END__.*$/\1/p')
  if [[ "$raw" == "ok" ]]; then
    SSH_LAST_STATUS=0
    SSH_LAST_ERROR=""
    return 0
  fi

  SSH_LAST_STATUS=1
  SSH_LAST_ERROR="Respon SSH tidak memuat sentinel __BEGIN__/__END__."
  return 1
}

# ====== rsync/tar ======
rsync_opts_build(){
  local base="-a --delete --partial"
  local extra=""
  rsync --version >/dev/null 2>&1 || { echo "$base"; return; }
  if rsync --help | grep -q 'info=progress2'; then extra="$extra --info=progress2"; else extra="$extra --progress"; fi
  if rsync --help | grep -q 'append-verify'; then extra="$extra --append-verify"; else extra="$extra --append"; fi
  echo "$base $extra"
}

rsync_pull(){
  local src="$1" dst="$2"
  local opts; opts="$(rsync_opts_build)"
  build_ssh_base
  local ssh_tun="$SSH_BASE_CMD"
  mkdir -p "$dst"
  if [[ "$DRY_RUN" == "1" ]]; then
    # shellcheck disable=SC2086
    rsync -n ${opts} -e "$ssh_tun" "$src/" "$dst/"
  fi
  # shellcheck disable=SC2086
  rsync ${opts} -e "$ssh_tun" "$src/" "$dst/"
}

tar_pull(){
  local src_dir="$1" dst_dir="$2"
  build_ssh_base
  local ssh_cmd="$SSH_BASE_CMD"
  mkdir -p "$dst_dir"
  if command -v pigz >/dev/null 2>&1; then
    eval "$ssh_cmd 'tar -C \"$(dirname "$src_dir")\" -cpf - \"$(basename "$src_dir")\" | pigz -1'" | pigz -d | tar -C "$dst_dir/.." -xpf -
  else
    eval "$ssh_cmd 'tar -C \"$(dirname "$src_dir")\" -cpf - \"$(basename "$src_dir")\" | gzip -1'" | gzip -d | tar -C "$dst_dir/.." -xpf -
  fi
}

# ====== Profile ======
profile_path(){ echo "$PROFILE_DIR/${SUBDOMAIN}.conf"; }

save_profile(){
  [[ -n "$SUBDOMAIN" ]] || { err "SUBDOMAIN kosong"; return 1; }
  cat > "$(profile_path)" <<EOF
SUBDOMAIN="$SUBDOMAIN"
SRC_HOST="$SRC_HOST"
SRC_USER="$SRC_USER"
SRC_PORT="$SRC_PORT"
SSHPASS="$SSHPASS"
SRC_WEBROOT="$SRC_WEBROOT"
DST_WEBROOT="$DST_WEBROOT"
WANT_DB="$WANT_DB"
DB_NAME="$DB_NAME"
DB_USER="$DB_USER"
DB_PASS="$DB_PASS"
T_DB="$T_DB"
T_USER="$T_USER"
T_PASS="$T_PASS"
NO_NGINX="$NO_NGINX"
DRY_RUN="$DRY_RUN"
FORCE_RSYNC="$FORCE_RSYNC"
EOF
  notify "Profil disimpan: $(profile_path)"
}

load_profile(){
  local p="$1"
  [[ -f "$PROFILE_DIR/$p" ]] || { err "Profil tidak ditemukan"; return 1; }
  # shellcheck disable=SC1090
  . "$PROFILE_DIR/$p"
  SUBDOMAIN="${SUBDOMAIN:-}"
  DST_WEBROOT="${DST_WEBROOT:-/var/www/${SUBDOMAIN}}"
  notify "Profil dimuat: $p"
}

list_profiles(){
  ls -1 "$PROFILE_DIR" 2>/dev/null | sed 's/\.conf$//' || true
}

remote_subdomains_fetch(){
  local cmd
  cmd=$(cat <<'CMD'
(
  for path in /etc/nginx/sites-enabled /etc/nginx/conf.d /etc/nginx/sites-available; do
    if [ -d "$path" ]; then
      grep -RhoE "server_name[[:space:]]+[^;#]*" "$path" 2>/dev/null
    fi
  done
) | awk "{for (i=2; i<=NF; i++) {gsub(/;$/,"", $i); if (length($i) > 0 && index($i, ".") > 0) print $i;}}" | sort -u
CMD
  )
  remote_marked "$cmd" | tr -d '\r' | sed '/^[[:space:]]*$/d'
}

remote_subdomain_menu(){
  log "Mengambil daftar subdomain (server_name) dari SOURCE..."
  local raw; raw="$(remote_subdomains_fetch || true)"
  raw="$(printf '%s\n' "$raw" | sed '/^[[:space:]]*$/d')"
  if [[ -z "$raw" ]]; then
    warn "Tidak menemukan daftar subdomain dari konfigurasi Nginx SOURCE."
    return
  fi

  local -a subdomain_list=()
  mapfile -t subdomain_list <<<"$raw"
  if [[ ${#subdomain_list[@]} -eq 0 ]]; then
    warn "Daftar subdomain kosong."
    return
  fi

  echo "==================== DAFTAR SUBDOMAIN SOURCE ===================="
  local idx
  for idx in "${!subdomain_list[@]}"; do
    printf " %2d) %s\n" "$((idx + 1))" "${subdomain_list[$idx]}"
  done
  echo "-----------------------------------------------------------------"
  local selection
  read -r -p "Pilih nomor untuk set SUBDOMAIN atau ketik manual (Enter=skip): " selection || true

  if [[ "$selection" =~ ^[0-9]+$ ]]; then
    local index=$((selection - 1))
    if (( index >= 0 && index < ${#subdomain_list[@]} )); then
      local chosen="${subdomain_list[$index]}"
      chosen="$(sanitize "$chosen")"
      if [[ -n "$chosen" ]]; then
        SUBDOMAIN="$chosen"
        DST_WEBROOT="/var/www/${SUBDOMAIN}"
        SRC_WEBROOT=""
        notify "SUBDOMAIN di-set ke $SUBDOMAIN (DST webroot direset ke default)."
        save_profile
      fi
    else
      warn "Nomor di luar jangkauan daftar subdomain."
    fi
    return
  fi

  if [[ -n "$selection" ]]; then
    local manual
    manual="$(sanitize "$selection")"
    if [[ -n "$manual" ]]; then
      SUBDOMAIN="$manual"
      DST_WEBROOT="/var/www/${SUBDOMAIN}"
      SRC_WEBROOT=""
      notify "SUBDOMAIN di-set ke $SUBDOMAIN (input manual)."
      save_profile
    else
      warn "Input manual kosong setelah disanitasi."
    fi
  fi
}

ensure_source_connection_ready(){
  local -a missing=()
  [[ -n "$SRC_HOST" ]] || missing+=("SRC_HOST")
  [[ -n "$SRC_USER" ]] || missing+=("SRC_USER")
  [[ -n "$SRC_PORT" ]] || missing+=("SRC_PORT")
  [[ -n "$SUBDOMAIN" ]] || missing+=("SUBDOMAIN")

  if (( ${#missing[@]} > 0 )); then
    err "Profil belum lengkap: ${missing[*]}. Jalankan menu '2) Set Source Connection (Quick)'."
    return 1
  fi
  return 0
}

# ====== Steps ======
deps_menu(){
  local mode="${1:-}"
  local auto_mode=0
  if [[ "$mode" == "--auto" ]]; then
    auto_mode=1
  fi

  echo "Memeriksa dependencies..."
  local missing=0
  for bin in ssh rsync mysql mysqldump awk sed tar gzip; do
    if ! need "$bin"; then missing=1; fi
  done
  if [[ -n "$SSHPASS" ]]; then
    if ! need sshpass; then
      warn "sshpass belum terpasang padahal SSHPASS digunakan. Install: apt-get install -y sshpass"
      missing=1
    fi
  fi
  if [[ "$missing" == "0" ]]; then
    notify "✅ Dependencies OK"
  else
    warn "Ada dependency yang belum lengkap."
  fi

  if [[ "${auto_mode:-0}" -ne 1 ]]; then
    pause
  fi
  return $missing
}

source_connection_menu(){
  echo "Set Source Connection (Quick). Isikan untuk menyiapkan koneksi dasar sebelum menjalankan ONE-CLICK."
  local input usepass default_usepass test_now

  read -r -p "Sub-domain (mis: blog.domain.com) [${SUBDOMAIN:-}]: " input
  if [[ -n "$input" ]]; then
    local sanitized; sanitized="$(sanitize "$input")"
    if [[ -n "$sanitized" ]]; then
      SUBDOMAIN="$sanitized"
      DST_WEBROOT="/var/www/${SUBDOMAIN}"
      SRC_WEBROOT=""
      notify "SUBDOMAIN di-set ke $SUBDOMAIN"
    else
      warn "Input subdomain kosong setelah disanitasi."
    fi
  fi

  read -r -p "IP/Host server LAMA (SOURCE) [${SRC_HOST:-}]: " input
  if [[ -n "$input" ]]; then
    SRC_HOST="$input"
  fi

  read -r -p "User SSH SOURCE [${SRC_USER:-root}]: " input
  SRC_USER="${input:-${SRC_USER:-root}}"

  read -r -p "Port SSH SOURCE [${SRC_PORT:-22}]: " input
  SRC_PORT="${input:-${SRC_PORT:-22}}"

  default_usepass="N"
  [[ -n "$SSHPASS" ]] && default_usepass="Y"
  read -r -p "Gunakan password/sshpass? (y/N) [$default_usepass]: " usepass
  usepass="${usepass:-$default_usepass}"

  if [[ "$usepass" =~ ^[Yy]$ ]]; then
    if need sshpass; then
      read -r -s -p "Password SSH SOURCE ($SRC_USER@$SRC_HOST): " SSHPASS; echo
    else
      warn "sshpass belum ada; install dulu di menu Dependencies."
      SSHPASS=""
    fi
  else
    SSHPASS=""
  fi

  if [[ -z "$SRC_HOST" ]]; then
    warn "SRC_HOST masih kosong. Lengkapi sebelum melanjutkan."
  fi

  if [[ -n "$SUBDOMAIN" ]]; then
    save_profile
  else
    warn "SUBDOMAIN masih kosong; isi agar profil dapat disimpan."
  fi

  read -r -p "Tes koneksi sekarang? (Y/n) [Y]: " test_now
  test_now="${test_now:-Y}"
  if [[ "$test_now" =~ ^[Yy]$ ]]; then
    if ! test_connect_menu; then
      warn "Tes koneksi gagal. Periksa kembali host/user/password sebelum melanjutkan."
    fi
  else
    pause
  fi
}

new_profile_menu(){
  local input usepass default_usepass
  read -r -p "Sub-domain (mis: blog.domain.com): " SUBDOMAIN
  SUBDOMAIN="$(sanitize "$SUBDOMAIN")"

  read -r -p "IP/Host server LAMA (SOURCE) [${SRC_HOST:-}]: " input
  if [[ -n "$input" ]]; then
    SRC_HOST="$input"
  fi

  read -r -p "User SSH SOURCE [${SRC_USER:-root}]: " input
  SRC_USER="${input:-${SRC_USER:-root}}"

  read -r -p "Port SSH SOURCE [${SRC_PORT:-22}]: " input
  SRC_PORT="${input:-${SRC_PORT:-22}}"

  default_usepass="N"
  [[ -n "$SSHPASS" ]] && default_usepass="Y"
  read -r -p "Pakai password (y/N)? Jika y, akan diminta password setelah tes koneksi [$default_usepass]: " usepass
  usepass="${usepass:-$default_usepass}"

  DST_WEBROOT="/var/www/${SUBDOMAIN}"
  SRC_WEBROOT=""   # biarkan auto
  WANT_DB="auto"   # auto detect

  if [[ "$usepass" =~ ^[Yy]$ ]]; then
    if need sshpass; then
      read -r -s -p "Password SSH SOURCE ($SRC_USER@$SRC_HOST): " SSHPASS; echo
    else
      warn "sshpass belum ada; install dulu di menu Dependencies."
      SSHPASS=""
    fi
  else
    SSHPASS=""
  fi

  save_profile
  pause
}

load_profile_menu(){
  echo "Profil tersedia:"
  list_profiles
  read -r -p "Ketik nama profil (tanpa .conf): " name
  load_profile "${name}.conf" || true
  pause
}

test_connect_menu(){
  local mode="${1:-}"
  local auto_mode=0
  if [[ "$mode" == "--auto" ]]; then
    auto_mode=1
  fi

  if [[ -z "$SRC_HOST" ]]; then
    err "Profil belum lengkap (SRC_HOST kosong)"
    if [[ "${auto_mode:-0}" -ne 1 ]]; then pause; fi
    return 1
  fi

  SRC_USER="${SRC_USER:-root}"
  SRC_PORT="${SRC_PORT:-22}"

  log "Tes koneksi SSH ke $SRC_USER@$SRC_HOST:$SRC_PORT ..."
  if ssh_check; then
    notify "✅ SSH non-interaktif OK"
    if [[ "${auto_mode:-0}" -eq 1 ]]; then
      log "Mode auto: lewati pemilihan subdomain interaktif."
    else
      remote_subdomain_menu
    fi
  else
    if [[ "$SSHPASS_FALLBACK" == "1" ]]; then
      if [[ "$SSHPASS_WARNED" != "1" ]]; then
        err "SSHPASS diisi tetapi utilitas 'sshpass' belum terpasang. Install sshpass atau kosongkan password untuk memakai SSH key."
        SSHPASS_WARNED="1"
      fi
    elif [[ -n "$SSHPASS" ]]; then
      case "$SSH_LAST_STATUS" in
        5|6)
          warn "Autentikasi password gagal (kode $SSH_LAST_STATUS). Pastikan password benar dan root login diizinkan."
          ;;
        255)
          warn "Tidak bisa membuka koneksi ke $SRC_HOST:$SRC_PORT. Periksa firewall, IP, atau konfirmasi fingerprint host (misal server Lempzy)."
          ;;
        *)
          warn "SSH pass mungkin salah atau root login ditolak oleh SOURCE (exit $SSH_LAST_STATUS)."
          ;;
      esac
    else
      case "$SSH_LAST_STATUS" in
        255)
          warn "Tidak bisa membuka koneksi ke $SRC_HOST:$SRC_PORT. Firewall, IP salah, atau butuh approve fingerprint manual."
          ;;
        *)
          warn "SSH key tidak bekerja. Opsi: jalankan 'ssh-copy-id -p $SRC_PORT $SRC_USER@$SRC_HOST' atau set SSHPASS + install sshpass."
          ;;
      esac
    fi
    if [[ -n "$SSH_LAST_ERROR" ]]; then
      warn "Detail SSH: $SSH_LAST_ERROR"
    fi
    if [[ "${auto_mode:-0}" -ne 1 ]]; then pause; fi
    return 1
  fi

  if [[ "${auto_mode:-0}" -ne 1 ]]; then
    pause
  fi
  return 0
}

detect_webroot_menu(){
  local mode="${1:-}"
  local auto_mode=0
  if [[ "$mode" == "--auto" ]]; then
    auto_mode=1
  fi

  if [[ -z "$SUBDOMAIN" || -z "$SRC_HOST" ]]; then
    err "Profil belum lengkap"
    if [[ "${auto_mode:-0}" -ne 1 ]]; then pause; fi
    return 1
  fi

  if [[ -z "$SRC_WEBROOT" ]]; then
    log "Deteksi webroot via Nginx SOURCE..."
    local conf; conf="$(remote_marked "grep -RIl \"server_name[[:space:]]\\+${SUBDOMAIN}[;]\" /etc/nginx/sites-enabled 2>/dev/null | head -n1" | head -n1 || true)"
    if [[ -n "$conf" ]]; then
      SRC_WEBROOT="$(remote_marked "awk '/^[[:space:]]*root[[:space:]]/ && \$0 !~ /#/{print \$2}' \"$conf\" | sed 's/;//' | head -n1" | tr -d '\r' | head -n1 || true)"
    fi
    [[ -z "$SRC_WEBROOT" ]] && SRC_WEBROOT="/var/www/${SUBDOMAIN}"
    log "SOURCE webroot: $SRC_WEBROOT"
    save_profile
  else
    log "SOURCE webroot sudah di-set: $SRC_WEBROOT"
  fi

  if [[ "${auto_mode:-0}" -ne 1 ]]; then
    pause
  fi
  return 0
}

detect_db_menu(){
  local mode="${1:-}"
  local auto_mode=0
  if [[ "$mode" == "--auto" ]]; then
    auto_mode=1
  fi

  if [[ -z "$SRC_WEBROOT" ]]; then
    err "Set/deteksi webroot dulu"
    if [[ "${auto_mode:-0}" -ne 1 ]]; then pause; fi
    return 1
  fi
  if [[ "$WANT_DB" == "no" ]]; then
    warn "DB diset tidak akan dipindah (NO_DB)."
    if [[ "${auto_mode:-0}" -ne 1 ]]; then pause; fi
    return 0
  fi

  log "Cari wp-config.php di SOURCE..."
  local WPC; WPC="$(remote_marked "find \"$SRC_WEBROOT\" -maxdepth 3 -type f -name wp-config.php 2>/dev/null | head -n1" | tr -d '\r' || true)"
  if [[ -z "$WPC" ]]; then
    local parent; parent="$(remote_marked "dirname \"$SRC_WEBROOT\"" | tr -d '\r' || true)"
    WPC="$(remote_marked "find \"$parent\" -maxdepth 2 -type f -name wp-config.php 2>/dev/null | head -n1" | tr -d '\r' || true)"
  fi

  if [[ -n "$WPC" ]]; then
    log "wp-config.php: $WPC"
    local hasphp; hasphp="$(remote_marked "command -v php >/dev/null && echo yes || echo no" | tr -d '\r')"
    local out
    if [[ "$hasphp" == "yes" ]]; then
      out="$(remote_marked "php -r '\
        \$c=@file_get_contents(\"$WPC\");\
        function g(\$k,\$c){ if(preg_match(\"/define\\(\\s*\\'\".\$k.\"\\'\\s*,\\s*\\'([^\\']*)\\'\\s*\\)/\", \$c, \$m)){echo \$m[1].\"\\n\";} else {echo \"\\n\";} }\
        g(\"DB_NAME\", \$c); g(\"DB_USER\", \$c); g(\"DB_PASSWORD\", \$c);\
      '")"
    else
      out="$(remote_marked "echo \"\$(grep -E \"define\\(\\s*'DB_NAME'\" \"$WPC\" | sed -E \"s/.*'DB_NAME'\\s*,\\s*'([^']*)'.*/\\1/\")\"; \
                             echo \"\$(grep -E \"define\\(\\s*'DB_USER'\" \"$WPC\" | sed -E \"s/.*'DB_USER'\\s*,\\s*'([^']*)'.*/\\1/\")\"; \
                             echo \"\$(grep -E \"define\\(\\s*'DB_PASSWORD'\" \"$WPC\" | sed -E \"s/.*'DB_PASSWORD'\\s*,\\s*'([^']*)'.*/\\1/\")\"")"
    fi
    DB_NAME="$(printf '%s\n' "$out" | sed -n '1p')"; DB_USER="$(printf '%s\n' "$out" | sed -n '2p')"; DB_PASS="$(printf '%s\n' "$out" | sed -n '3p')"
    DB_NAME="$(sanitize "${DB_NAME:-}")"; DB_USER="$(sanitize "${DB_USER:-}")"
    if [[ -n "${DB_NAME:-}" ]]; then
      notify "Deteksi DB: name=$DB_NAME user=$DB_USER (password: $( [[ -n "${DB_PASS:-}" ]] && echo ada || echo kosong ))"
      WANT_DB="yes"
      # set default target creds (bisa diubah manual via edit profil)
      T_DB="${T_DB:-$DB_NAME}"
      T_USER="${T_USER:-${DB_USER:-${SUBDOMAIN//./_}}}"
      [[ -z "${T_PASS:-}" ]] && T_PASS="$(tr -dc A-Za-z0-9 </dev/urandom | head -c 20)"
      save_profile
    else
      warn "Tidak bisa ekstrak DB dari wp-config.php; set WANT_DB=no jika ingin skip."
      WANT_DB="no"
      save_profile
    fi
  else
    warn "wp-config.php tidak ditemukan; set WANT_DB=no jika hanya copy file."
    WANT_DB="no"
    save_profile
  fi
  if [[ "${auto_mode:-0}" -ne 1 ]]; then
    pause
  fi
  return 0
}

migrate_files_menu(){
  local mode="${1:-}"
  local auto_mode=0
  if [[ "$mode" == "--auto" ]]; then
    auto_mode=1
  fi

  if [[ -z "$SUBDOMAIN" || -z "$SRC_WEBROOT" ]]; then
    err "Profil belum lengkap (subdomain/webroot)"
    if [[ "$auto_mode" -ne 1 ]]; then pause; fi
    return 1
  fi
  DST_WEBROOT="${DST_WEBROOT:-/var/www/${SUBDOMAIN}}"
  mkdir -p "$DST_WEBROOT"

  local est; est="$(remote_marked "du -sb \"$SRC_WEBROOT\" 2>/dev/null | awk '{print \$1}'" | tr -d '\r' || true)"
  [[ -z "${est:-}" ]] && est=0
  log "Perkiraan size SOURCE: $(bytes_to_h "$est")"

  if [[ "${auto_mode:-0}" -eq 1 ]]; then
    FORCE_RSYNC="1"
    DRY_RUN="0"
  else
    read -r -p "Pakai rsync (Y) atau tar fallback (t)? [Y/t]: " choice; choice="${choice:-Y}"
    if [[ "$choice" =~ ^[Tt]$ ]]; then FORCE_RSYNC="0"; else FORCE_RSYNC="1"; fi
    read -r -p "Dry-run dulu untuk rsync? (y/N): " dry; dry="${dry:-N}"; [[ "$dry" =~ ^[Yy]$ ]] && DRY_RUN="1" || DRY_RUN="0"
  fi
  save_profile

  notify "Mulai tarik FILES..."
  local status=0
  if [[ "$FORCE_RSYNC" == "1" ]]; then
    if ! rsync_pull "${SRC_USER}@${SRC_HOST}:${SRC_WEBROOT}" "${DST_WEBROOT}"; then
      warn "rsync gagal, fallback ke tar stream"
      if ! tar_pull "${SRC_WEBROOT}" "${DST_WEBROOT}"; then
        err "Tar fallback gagal"
        status=1
      fi
    fi
  else
    if ! tar_pull "${SRC_WEBROOT}" "${DST_WEBROOT}"; then
      err "Tar fallback gagal"
      status=1
    fi
  fi
  if [[ $status -eq 0 ]]; then
    notify "FILES selesai."
  fi

  if [[ "${auto_mode:-0}" -ne 1 ]]; then
    pause
  fi
  return $status
}

import_db_menu(){
  local mode="${1:-}"
  local auto_mode=0
  if [[ "$mode" == "--auto" ]]; then
    auto_mode=1
  fi

  if [[ "$WANT_DB" != "yes" || -z "${DB_NAME:-}" ]]; then
    warn "Import DB dilewati (tidak terdeteksi atau dinonaktifkan)."
    if [[ "${auto_mode:-0}" -ne 1 ]]; then pause; fi
    return 0
  fi

  T_DB="${T_DB:-$DB_NAME}"
  T_USER="${T_USER:-${DB_USER:-${SUBDOMAIN//./_}}}"
  T_PASS="${T_PASS:-$(tr -dc A-Za-z0-9 </dev/urandom | head -c 20)}"

  mysql -e "CREATE DATABASE IF NOT EXISTS \`$T_DB\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
  mysql -e "CREATE USER IF NOT EXISTS '$T_USER'@'%' IDENTIFIED BY '$T_PASS';" || true
  mysql -e "GRANT ALL PRIVILEGES ON \`$T_DB\`.* TO '$T_USER'@'%'; FLUSH PRIVILEGES;"

  local dump_cmd
  if [[ -n "${DB_PASS:-}" ]]; then
    dump_cmd="mysqldump -u\"$DB_USER\" -p\"$DB_PASS\" --single-transaction --quick --routines --triggers --events \"$DB_NAME\" | gzip -1"
  else
    dump_cmd="mysqldump -u\"${DB_USER:-root}\" --single-transaction --quick --routines --triggers --events \"$DB_NAME\" | gzip -1"
  fi

  notify "Menarik & import DB..."
  local status=0
  if ! remote_marked "$dump_cmd" | gzip -d | mysql "$T_DB"; then
    err "Import DB gagal"
    status=1
  else
    notify "Import DB selesai → target: $T_DB (user=$T_USER)"
    save_profile

    # Patch wp-config.php target (jika ada)
    if [[ -f "$DST_WEBROOT/wp-config.php" ]]; then
      sed -ri "s/define\('DB_NAME',[[:space:]]*'[^']*'\)/define('DB_NAME', '$T_DB')/" "$DST_WEBROOT/wp-config.php" || true
      sed -ri "s/define\('DB_USER',[[:space:]]*'[^']*'\)/define('DB_USER', '$T_USER')/" "$DST_WEBROOT/wp-config.php" || true
      sed -ri "s/define\('DB_PASSWORD',[[:space:]]*'[^']*'\)/define('DB_PASSWORD', '$T_PASS')/" "$DST_WEBROOT/wp-config.php" || true
    fi
  fi

  if [[ "${auto_mode:-0}" -ne 1 ]]; then
    pause
  fi
  return $status
}

nginx_menu(){
  local mode="${1:-}"
  local auto_mode=0
  if [[ "$mode" == "--auto" ]]; then
    auto_mode=1
  fi

  local yn
  if [[ "${auto_mode:-0}" -eq 1 ]]; then
    if [[ "$NO_NGINX" == "1" ]]; then
      log "Mode auto: konfigurasi Nginx dilewati karena NO_NGINX=1."
      return 0
    fi
    yn="Y"
  else
    read -r -p "Tulis block Nginx? (Y/n) [Y]: " yn
    yn="${yn:-Y}"
  fi
  if [[ "$yn" =~ ^[Nn]$ ]]; then
    NO_NGINX="1"
    save_profile
    if [[ "${auto_mode:-0}" -ne 1 ]]; then pause; fi
    return 0
  fi
  NO_NGINX="0"
  save_profile

  local SOCK; SOCK="$(phpfpm_sock_guess)"
  local SCONF="/etc/nginx/sites-available/${SUBDOMAIN}.conf"
  [[ -z "$DST_WEBROOT" ]] && DST_WEBROOT="/var/www/${SUBDOMAIN}"
  if [[ ! -f "$SCONF" ]]; then
    cat > "$SCONF" <<CONF
server {
    listen 80;
    server_name ${SUBDOMAIN};
    root ${DST_WEBROOT};
    index index.php index.html;

    location / { try_files \$uri \$uri/ /index.php?\$query_string; }

    location ~ \\.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:${SOCK};
    }

    location ~* \\.(jpg|jpeg|png|gif|webp|svg|css|js|ico|woff2?)$ {
        expires max; access_log off; log_not_found off;
    }
}
CONF
    ln -sf "$SCONF" "/etc/nginx/sites-enabled/${SUBDOMAIN}.conf"
  fi

  local status=0
  if nginx -t; then
    systemctl reload nginx || { warn "Nginx reload gagal; cek config."; status=1; }
  else
    warn "Nginx test gagal; periksa konfigurasi."
    status=1
  fi

  if [[ "${auto_mode:-0}" -ne 1 ]]; then
    pause
  fi
  return $status
}

finalize_menu(){
  local mode="${1:-}"
  local auto_mode=0
  if [[ "$mode" == "--auto" ]]; then
    auto_mode=1
  fi

  [[ -z "$DST_WEBROOT" ]] && DST_WEBROOT="/var/www/${SUBDOMAIN}"
  chown -R www-data:www-data "$DST_WEBROOT" || true
  systemctl list-units | grep -Eo 'php[0-9.]+-fpm\.service' | sort -u | xargs -r -n1 systemctl reload || true
  notify "Selesai. Arahkan DNS A record ${SUBDOMAIN} ke IP server baru saat siap cutover."
  log "Log selesai: $LOG_FILE"

  if [[ "${auto_mode:-0}" -ne 1 ]]; then
    pause
  fi
  return 0
}

one_click_run(){
  if ! ensure_source_connection_ready; then
    pause
    return
  fi

  if ! deps_menu --auto; then
    err "Langkah dependencies gagal. Periksa menu 1."
    pause
    return
  fi

  if ! test_connect_menu --auto; then
    err "Tes SSH gagal. Pastikan kredensial benar di menu 2."
    pause
    return
  fi

  if ! detect_webroot_menu --auto; then
    err "Deteksi webroot gagal. Jalankan menu 6 secara manual."
    pause
    return
  fi

  if ! detect_db_menu --auto; then
    err "Deteksi database gagal. Periksa menu 7."
    pause
    return
  fi

  if ! migrate_files_menu --auto; then
    err "Penarikan file gagal. Coba ulang dari menu 8."
    pause
    return
  fi

  if ! import_db_menu --auto; then
    err "Import database gagal. Coba ulang dari menu 9."
    pause
    return
  fi

  if ! nginx_menu --auto; then
    err "Penulisan block Nginx gagal. Revisi di menu 10."
    pause
    return
  fi

  if ! finalize_menu --auto; then
    err "Finalize gagal. Jalankan menu 11 untuk detail."
    pause
    return
  fi

  notify "ONE-CLICK selesai tanpa error kritis."
  pause
}

# ====== UI ======
main_menu(){
  while true; do
    clear
    echo "==================== SUBDOMAIN PULL MIGRATION (MENU) ===================="
    echo "Subdomain : ${SUBDOMAIN:-<belum>}"
    echo "Source    : ${SRC_USER:-?}@${SRC_HOST:-?}:${SRC_PORT:-?}"
    echo "Webroot   : SRC=${SRC_WEBROOT:-<auto>}  DST=${DST_WEBROOT:-/var/www/<subdomain>}"
    echo "DB        : WANT_DB=${WANT_DB}  SRC=${DB_NAME:-<auto>}  TARGET=${T_DB:-<auto>}"
    echo "Auth      : $( [[ -n "$SSHPASS" ]] && echo 'PASSWORD/sshpass' || echo 'SSH KEY (BatchMode)')"
    echo "Log file  : $LOG_FILE"
    echo "-------------------------------------------------------------------------"
    if [[ -z "$SRC_HOST" || -z "$SUBDOMAIN" ]]; then
      echo "NOTE: Jalankan menu '2) Set Source Connection (Quick)' sebelum ONE-CLICK."
    fi
    echo " 1) Dependencies Check"
    echo " 2) Set Source Connection (Quick)"
    echo " 3) New Profile"
    echo " 4) Load Profile"
    echo " 5) Test SSH Connectivity"
    echo " 6) Detect Webroot (Nginx)"
    echo " 7) Detect DB (wp-config.php)"
    echo " 8) Migrate Files"
    echo " 9) Import Database"
    echo "10) Write Nginx Block"
    echo "11) Finalize (Ownership + Reload)"
    echo "12) ONE-CLICK RUN (Deps→Finalize)"
    echo " 0) Exit"
    echo "-------------------------------------------------------------------------"
    read -r -p "Pilih menu [0-12]: " ans
    case "$ans" in
      1) deps_menu || true ;;
      2) source_connection_menu || true ;;
      3) new_profile_menu || true ;;
      4) load_profile_menu || true ;;
      5) test_connect_menu || true ;;
      6) detect_webroot_menu || true ;;
      7) detect_db_menu || true ;;
      8) migrate_files_menu || true ;;
      9) import_db_menu || true ;;
     10) nginx_menu || true ;;
     11) finalize_menu || true ;;
     12) one_click_run || true ;;
      0) exit 0 ;;
      *) echo "Pilihan tidak dikenal"; pause ;;
    esac
  done
}

trap 'notify "❌ Terjadi error. Lihat log: '"$LOG_FILE"'"' ERR
main_menu
