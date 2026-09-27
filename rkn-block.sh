#!/usr/bin/env bash
# rkn-block — блокировка подсетей сканеров через ipset + iptables на сервере с UFW.
#
# Что делает:
#   * скачивает списки подсетей (только https), проверяет их и только потом применяет;
#   * никогда не блокирует allow-лист: служебные сети, адреса самого сервера,
#     текущие SSH-подключения и адреса из /etc/rkn-block/allow.list;
#   * подключает свою цепочку первой в INPUT через штатный хук UFW (/etc/ufw/after.init),
#     поэтому правила переживают перезагрузку и `ufw reload`, а `ufw disable` их снимает;
#   * обновляет списки по таймеру и командой `rkn-block update` атомарно (ipset swap),
#     счётчики заблокированных пакетов при этом не сбрасываются.
#
# Чего НЕ делает: не ставит и не включает UFW, не трогает /etc/ipset.conf и правила UFW,
# не обновляет сам себя из интернета, не отправляет никуда данные.
#
# Установка:   sudo bash rkn-block.sh install
# Справка:     rkn-block help

set -euo pipefail
umask 077

readonly SELF_PATH=/usr/local/sbin/rkn-block
readonly CONF_DIR=/etc/rkn-block
readonly CONF_FILE=$CONF_DIR/rkn-block.conf
readonly ALLOW_FILE=$CONF_DIR/allow.list
readonly EXTRA_FILE=$CONF_DIR/extra-block.list
readonly STATE_DIR=/var/lib/rkn-block
readonly SETS_SAVE=$STATE_DIR/sets.save
readonly STATS_FILE=$STATE_DIR/stats.json
readonly BLOCK_TXT=$STATE_DIR/block.txt
readonly LOCK_FILE=/run/rkn-block.lock
readonly UFW_HOOK=/etc/ufw/after.init
readonly UFW_HOOK_BACKUP=/etc/ufw/after.init.rkn-block.bak
readonly HOOK_MARK='# rkn-block hook'
readonly UNIT_DIR=/etc/systemd/system
readonly CHAIN=RKN-BLOCK
readonly LOG_PREFIX='rkn-block: '
readonly CONFIRM_TIMEOUT=300   # секунд на проверку после установки, потом автоматический откат
readonly SET_B4=rkn-block4 SET_B6=rkn-block6 SET_A4=rkn-allow4 SET_A6=rkn-allow6

# Сети, которые никогда не блокируются: из интернета сканеры оттуда не приходят,
# а внутри сервера там живут loopback, Docker, VPN-клиенты и т.п.
readonly RESERVED=(
    0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16
    172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4
    ::1/128 fc00::/7 fe80::/10 ff00::/8
)

# --- Настройки по умолчанию (переопределяются в /etc/rkn-block/rkn-block.conf) ---
LISTS_BASE=https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public
SOURCES=(
    "$LISTS_BASE/government_networks.list"
    "$LISTS_BASE/antiscanner.list"
    "$LISTS_BASE/skipa.list"
    "$EXTRA_FILE"
)
MIN_PREFIX_V4=16          # сеть шире /16 в списке = список испорчен, обновление отклоняется
MIN_PREFIX_V6=24
MAX_V4_ADDRESSES=4000000  # потолок суммарного числа блокируемых IPv4-адресов (сейчас ~310 тыс.)
MAX_ENTRIES=200000        # потолок числа записей на семейство после схлопывания
MAX_SHRINK_PERCENT=50     # список сократился больше чем на 50% — подозрительно, нужен --force
MAX_GROW_FACTOR=3         # число IPv4-адресов выросло больше чем в 3 раза — нужен --force
LOG_DROPS=no              # yes = писать отброшенные пакеты в журнал ядра (не чаще 10/мин)
PROTECT_DOCKER=yes        # yes = защищать и опубликованные порты Docker (цепочка DOCKER-USER)
DOWNLOAD_TIMEOUT=60

# --- Вспомогательные функции ---
info() { printf '[rkn-block] %s\n' "$*" >&2; }
warn() { printf '[rkn-block] ВНИМАНИЕ: %s\n' "$*" >&2; }
die()  { printf '[rkn-block] ОШИБКА: %s\n' "$*" >&2; exit 1; }

need_root() { [[ $EUID -eq 0 ]] || die "нужны права root (sudo)"; }

need_cmds() {
    local missing=() c
    for c in "$@"; do command -v "$c" >/dev/null 2>&1 || missing+=("$c"); done
    ((${#missing[@]} == 0)) || die "не найдены команды: ${missing[*]}
Установите: apt-get install ipset iptables python3 curl iproute2 util-linux"
}

load_config() {
    [[ -f $CONF_FILE ]] || return 0
    # Конфиг исполняется от root, поэтому он должен принадлежать root и не быть доступен на запись другим.
    local owner mode
    read -r owner mode < <(stat -c '%u %a' "$CONF_FILE")
    [[ $owner == 0 ]] || die "$CONF_FILE должен принадлежать root"
    (( (8#$mode & 8#022) == 0 )) || die "$CONF_FILE не должен быть доступен на запись группе/всем"
    # shellcheck source=/dev/null
    source "$CONF_FILE"
}

take_lock() { # $1: wait|nowait
    exec 9>"$LOCK_FILE"
    if [[ $1 == wait ]]; then
        flock -w 60 9 || die "не удалось дождаться другой операции rkn-block"
    else
        flock -n 9 || return 1
    fi
}

# Параметры семейств: iptables-команда, allow-набор, блок-набор, семейство ipset, цепочка UFW.
family_params() {
    case $1 in
        4) echo "iptables $SET_A4 $SET_B4 inet ufw-before-input" ;;
        6) echo "ip6tables $SET_A6 $SET_B6 inet6 ufw6-before-input" ;;
    esac
}

set_exists() { ipset -q list -n "$1" >/dev/null 2>&1; }

ensure_sets() {
    local fam ipt a b f u
    for fam in 4 6; do
        read -r ipt a b f u < <(family_params "$fam")
        set_exists "$a" || ipset create "$a" hash:net family "$f"
        set_exists "$b" || ipset create "$b" hash:net family "$f" maxelem 65536
    done
}

# Правило цепочки номер $3 для наборов $1 (allow) и $2 (block) → массив RULE.
chain_rule() {
    case $3 in
        1) RULE=(-m set --match-set "$1" src -j RETURN) ;;
        2) RULE=(-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN) ;;
        3) RULE=(-m set --match-set "$2" src -m limit --limit 10/min --limit-burst 5
                 -j LOG --log-prefix "$LOG_PREFIX" --log-level 4) ;;
        4) RULE=(-m set --match-set "$2" src -j DROP) ;;
    esac
}

wanted_rules() { if [[ $LOG_DROPS == yes ]]; then echo 1 2 3 4; else echo 1 2 4; fi; }

detach_family() {
    local ipt=$1
    while "$ipt" -w -D INPUT -j "$CHAIN" 2>/dev/null; do :; done
    while "$ipt" -w -D DOCKER-USER -j "$CHAIN" 2>/dev/null; do :; done
    "$ipt" -w -F "$CHAIN" 2>/dev/null || true
    "$ipt" -w -X "$CHAIN" 2>/dev/null || true
}

# Ставит переход в нашу цепочку первым правилом цепочки $2.
attach_first() {
    local ipt=$1 parent=$2 first
    first=$("$ipt" -w -S "$parent" | grep -m1 "^-A $parent " || true)
    [[ $first == "-A $parent -j $CHAIN" ]] && return 0
    while "$ipt" -w -D "$parent" -j "$CHAIN" 2>/dev/null; do :; done
    "$ipt" -w -I "$parent" 1 -j "$CHAIN"
    info "$ipt: $CHAIN подключена первой в $parent"
}

# Цепочка: allow → RETURN, установленные соединения → RETURN, [LOG], блок-лист → DROP.
# Переход в неё стоит первым в INPUT, до правил UFW (иначе разрешённые в UFW порты пропустят сканеры).
# Опубликованные порты Docker (-p) идут через FORWARD мимо INPUT и UFW, поэтому цепочка
# подключается ещё и первой в DOCKER-USER: Docker проверяет её до своих разрешающих правил.
ensure_family() {
    local ipt=$1 a=$2 b=$3 uchain=$4 n count ok=1 first
    local -a want
    read -ra want < <(wanted_rules)

    if ! "$ipt" -w -n -L "$uchain" >/dev/null 2>&1; then
        info "$ipt: UFW не запущен — блокировка не подключается"
        detach_family "$ipt"
        return 0
    fi

    "$ipt" -w -N "$CHAIN" 2>/dev/null || true
    count=$("$ipt" -w -S "$CHAIN" | grep -c "^-A $CHAIN " || true)
    ((count == ${#want[@]})) || ok=0
    if ((ok)); then
        for n in "${want[@]}"; do
            chain_rule "$a" "$b" "$n"
            "$ipt" -w -C "$CHAIN" "${RULE[@]}" 2>/dev/null || { ok=0; break; }
        done
    fi
    if ((!ok)); then
        "$ipt" -w -F "$CHAIN"
        for n in "${want[@]}"; do
            chain_rule "$a" "$b" "$n"
            "$ipt" -w -A "$CHAIN" "${RULE[@]}"
        done
        info "$ipt: цепочка $CHAIN собрана"
    fi

    attach_first "$ipt" INPUT
    if [[ $PROTECT_DOCKER == yes ]] && "$ipt" -w -n -L DOCKER-USER >/dev/null 2>&1; then
        attach_first "$ipt" DOCKER-USER
    else
        while "$ipt" -w -D DOCKER-USER -j "$CHAIN" 2>/dev/null; do :; done
    fi
}

ensure_all() {
    local fam ipt a b f u
    if ! set_exists "$SET_B4" && [[ -f $SETS_SAVE ]]; then
        ipset restore -exist -f "$SETS_SAVE" || warn "не удалось восстановить сохранённые наборы"
    fi
    ensure_sets
    for fam in 4 6; do
        read -r ipt a b f u < <(family_params "$fam")
        ensure_family "$ipt" "$a" "$b" "$u"
    done
}

detach_all() {
    detach_family iptables
    detach_family ip6tables
}

save_state() {
    mkdir -p "$STATE_DIR"
    ipset save "$SET_B4" > "$SETS_SAVE.tmp"
    ipset save "$SET_B6" >> "$SETS_SAVE.tmp"
    ipset save "$SET_A4" >> "$SETS_SAVE.tmp"
    ipset save "$SET_A6" >> "$SETS_SAVE.tmp"
    mv -f "$SETS_SAVE.tmp" "$SETS_SAVE"
}

# IP-адреса текущих SSH-подключений к серверу.
ssh_peers() {
    ss -Htnp state established 2>/dev/null | awk '/"sshd/ {print $4}' | while read -r peer; do
        peer=${peer%:*}; peer=${peer#[}; peer=${peer%]}; peer=${peer#::ffff:}
        printf '%s\n' "$peer"
    done | sort -u
}

strip_list() { [[ -f $1 ]] && sed -e 's/#.*//' -e 's/[[:space:]]//g' -e '/^$/d' "$1" || true; }

# Allow-лист с пометками источника: reserved / user / self / ssh.
build_allow() {
    local x
    for x in "${RESERVED[@]}"; do printf 'reserved\t%s\n' "$x"; done
    strip_list "$ALLOW_FILE" | sed 's/^/user\t/'
    ip -o addr show scope global 2>/dev/null | awk '{sub(/\/.*/, "", $4); print "self\t" $4}'
    ssh_peers | sed 's/^/ssh\t/'
}

# Проверка списков. Аргументы: allow-файл, файл прошлой статистики, каталог вывода, force(0/1),
# далее источники в виде "вид<TAB>метка<TAB>путь". Пишет sets.restore, block.txt, stats.json.
validate_lists() {
    MIN_PREFIX_V4=$MIN_PREFIX_V4 MIN_PREFIX_V6=$MIN_PREFIX_V6 MAX_V4_ADDRESSES=$MAX_V4_ADDRESSES \
    MAX_ENTRIES=$MAX_ENTRIES MAX_SHRINK_PERCENT=$MAX_SHRINK_PERCENT MAX_GROW_FACTOR=$MAX_GROW_FACTOR \
    SETS="$SET_B4 $SET_B6 $SET_A4 $SET_A6" \
    python3 - "$@" <<'PY'
import ipaddress, json, os, sys, time

allow_path, prev_path, out_dir, force = sys.argv[1:5]
force = force == "1"
sources = [s.split("\t", 2) for s in sys.argv[5:]]
E = os.environ
MIN = {4: int(E["MIN_PREFIX_V4"]), 6: int(E["MIN_PREFIX_V6"])}
MAX4, MAXN = int(E["MAX_V4_ADDRESSES"]), int(E["MAX_ENTRIES"])
SHRINK, GROW = int(E["MAX_SHRINK_PERCENT"]), float(E["MAX_GROW_FACTOR"])
SET_B4, SET_B6, SET_A4, SET_A6 = E["SETS"].split()
errors, warnings = [], []

def clean(raw):
    return raw.lstrip("﻿").split("#", 1)[0].strip()

# Allow-лист.
allow = []
with open(allow_path, encoding="utf-8", errors="replace") as f:
    for line in f:
        tag, _, value = line.rstrip("\n").partition("\t")
        value = clean(value)
        if not value:
            continue
        try:
            allow.append((tag, ipaddress.ip_network(value, strict=False)))
        except ValueError:
            warnings.append(f"allow-лист: пропущена некорректная запись {value!r}")
reserved = [n for t, n in allow if t == "reserved"]
important = [(t, n) for t, n in allow if t != "reserved"]

# Источники.
nets = {4: [], 6: []}
per_source = []
for kind, label, path in sources:
    bad, count, skipped = [], 0, 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for no, raw in enumerate(f, 1):
            s = clean(raw)
            if not s:
                continue
            try:
                net = ipaddress.ip_network(s, strict=False)
            except ValueError:
                bad.append((no, s))
                continue
            if net.prefixlen < MIN[net.version]:
                errors.append(f"{label}:{no}: слишком широкая сеть {net} (допускается не шире /{MIN[net.version]})")
                continue
            if any(net.version == r.version and net.overlaps(r) for r in reserved):
                skipped += 1
                continue
            nets[net.version].append(net)
            count += 1
    if bad:
        sample = ", ".join(f"строка {n}: {s[:40]!r}" for n, s in bad[:3])
        errors.append(f"{label}: {len(bad)} некорректных строк ({sample})")
    if count == 0 and kind == "remote":
        errors.append(f"{label}: в источнике нет ни одной сети")
    if skipped:
        warnings.append(f"{label}: пропущено {skipped} записей из служебных сетей (частные, loopback и т.п.)")
    per_source.append({"source": label, "networks": count})

c4 = list(ipaddress.collapse_addresses(nets[4]))
c6 = list(ipaddress.collapse_addresses(nets[6]))
addr4 = sum(n.num_addresses for n in c4)
if addr4 > MAX4:
    errors.append(f"список блокирует {addr4} IPv4-адресов — больше порога MAX_V4_ADDRESSES={MAX4}")
for fam, lst in ((4, c4), (6, c6)):
    if len(lst) > MAXN:
        errors.append(f"IPv{fam}: {len(lst)} записей — больше порога MAX_ENTRIES={MAXN}")

# Сравнение с прошлым успешным обновлением.
try:
    with open(prev_path) as f:
        prev = json.load(f)
except (OSError, ValueError):
    prev = None
if prev:
    guard = []
    total, prev_total = len(c4) + len(c6), prev.get("entries", 0)
    if prev_total and total < prev_total * (100 - SHRINK) / 100:
        guard.append(f"число записей упало с {prev_total} до {total}")
    prev_addr = prev.get("v4_addresses", 0)
    if prev_addr and addr4 > prev_addr * GROW:
        guard.append(f"число IPv4-адресов выросло с {prev_addr} до {addr4}")
    for g in guard:
        (warnings if force else errors).append(g + ("" if force else " — проверьте списки, применить: rkn-block update --force"))

# Важные адреса, попавшие в блок-лист: доступ к ним сохранит allow-правило, но о таком надо знать.
labels = {"user": "allow.list", "self": "адрес сервера", "ssh": "ваше SSH-подключение"}
for tag, a in important:
    for b in (c4 if a.version == 4 else c6):
        if a.overlaps(b):
            warnings.append(f"{a} ({labels.get(tag, tag)}) входит в блок-лист ({b}); доступ сохранится благодаря allow-правилу")
            break

for w in warnings:
    print(f"[rkn-block] ВНИМАНИЕ: {w}", file=sys.stderr)
if errors:
    for e in errors:
        print(f"[rkn-block] ОШИБКА: {e}", file=sys.stderr)
    print("[rkn-block] Списки НЕ применены, действуют прежние.", file=sys.stderr)
    sys.exit(2)

def maxelem(n):
    m = 65536
    while m < 2 * n:
        m *= 2
    return m

a4 = list(ipaddress.collapse_addresses(n for _, n in allow if n.version == 4))
a6 = list(ipaddress.collapse_addresses(n for _, n in allow if n.version == 6))
with open(os.path.join(out_dir, "sets.restore"), "w") as f:
    for name, family, lst in ((SET_B4, "inet", c4), (SET_B6, "inet6", c6), (SET_A4, "inet", a4), (SET_A6, "inet6", a6)):
        f.write(f"create {name}-new hash:net family {family} hashsize 1024 maxelem {maxelem(len(lst))}\n")
        f.writelines(f"add {name}-new {n}\n" for n in lst)
with open(os.path.join(out_dir, "block.txt"), "w") as f:
    f.writelines(f"{n}\n" for n in c4 + c6)
stats = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "entries": len(c4) + len(c6),
         "v4": len(c4), "v6": len(c6), "v4_addresses": addr4, "sources": per_source}
with open(os.path.join(out_dir, "stats.json"), "w") as f:
    json.dump(stats, f, ensure_ascii=False, indent=1)

for s in per_source:
    print(f"  {s['source']}: {s['networks']} сетей")
print(f"  Итого после схлопывания: IPv4 {len(c4)} записей ({addr4} адресов), IPv6 {len(c6)} записей")
print(f"  Allow-лист: IPv4 {len(a4)}, IPv6 {len(a6)} записей")
PY
}

apply_sets() {
    local restore=$1 s f
    for s in "$SET_B4" "$SET_B6" "$SET_A4" "$SET_A6"; do ipset -q destroy "$s-new" || true; done
    ipset restore -f "$restore"
    for s in "$SET_B4" "$SET_B6" "$SET_A4" "$SET_A6"; do
        f=inet; [[ $s == *6 ]] && f=inet6
        set_exists "$s" || ipset create "$s" hash:net family "$f"
        ipset swap "$s-new" "$s"
        ipset destroy "$s-new"
    done
}

# --- Команды ---

cmd_update() {
    local force=0 dry=0 arg
    for arg in "$@"; do
        case $arg in
            --force) force=1 ;;
            --dry-run|--check) dry=1 ;;
            *) die "неизвестный параметр: $arg" ;;
        esac
    done
    need_root
    need_cmds ipset iptables ip6tables python3 curl ss ip flock
    load_config
    take_lock wait

    local tmp i=0 src f
    tmp=$(mktemp -d /tmp/rkn-block.XXXXXXXX)
    # shellcheck disable=SC2064
    trap "rm -rf '$tmp'; for s in $SET_B4 $SET_B6 $SET_A4 $SET_A6; do ipset -q destroy \"\$s-new\" || true; done" EXIT

    local -a specs=()
    for src in "${SOURCES[@]}"; do
        i=$((i + 1)); f=$tmp/src.$i
        if [[ $src == /* ]]; then
            if [[ -f $src ]]; then cp "$src" "$f"; else : > "$f"; fi
            specs+=("local"$'\t'"$src"$'\t'"$f")
        elif [[ $src == https://* ]]; then
            info "Загрузка $src"
            curl -fsSL --proto '=https' --tlsv1.2 --retry 2 --max-time "$DOWNLOAD_TIMEOUT" \
                --max-filesize 8388608 -o "$f" "$src" \
                || die "не удалось скачать $src — списки не изменены"
            specs+=("remote"$'\t'"$src"$'\t'"$f")
        else
            die "источник должен быть https:// или абсолютным путём к файлу: $src"
        fi
    done

    build_allow > "$tmp/allow.txt"
    info "Проверка списков"
    validate_lists "$tmp/allow.txt" "$STATS_FILE" "$tmp" "$force" "${specs[@]}"

    if ((dry)); then
        info "Проверка пройдена (--dry-run: ничего не применено)"
        return 0
    fi

    apply_sets "$tmp/sets.restore"
    ensure_all
    save_state
    install -m 0644 "$tmp/stats.json" "$STATS_FILE"
    install -m 0644 "$tmp/block.txt" "$BLOCK_TXT"
    info "Списки применены"
}

cmd_ensure() { # из таймера: не ждём, если идёт другая операция
    need_root
    load_config
    take_lock nowait || exit 0
    ensure_all
}

cmd_hook() {
    need_root
    load_config
    take_lock wait
    case $1 in
        start) ensure_all ;;
        stop) detach_all ;;
    esac
}

cmd_status() {
    need_root
    load_config
    local fam ipt a b f u first
    for fam in 4 6; do
        read -r ipt a b f u < <(family_params "$fam")
        first=$("$ipt" -w -S INPUT 2>/dev/null | grep -m1 '^-A INPUT ' || true)
        if [[ $first == "-A INPUT -j $CHAIN" ]]; then
            printf 'IPv%s: INPUT защищён, ' "$fam"
        else
            printf 'IPv%s: INPUT НЕ защищён, ' "$fam"
        fi
        if "$ipt" -w -n -L DOCKER-USER >/dev/null 2>&1; then
            first=$("$ipt" -w -S DOCKER-USER | grep -m1 '^-A DOCKER-USER ' || true)
            if [[ $first == "-A DOCKER-USER -j $CHAIN" ]]; then
                printf 'Docker защищён, '
            else
                printf 'Docker НЕ защищён, '
            fi
        fi
        printf 'в блок-листе %s записей, в allow %s; ' \
            "$(ipset -t list "$b" 2>/dev/null | awk '/Number of entries/ {print $4}')" \
            "$(ipset -t list "$a" 2>/dev/null | awk '/Number of entries/ {print $4}')"
        { "$ipt" -w -nvxL "$CHAIN" 2>/dev/null || true; } \
            | awk '$3 == "DROP" {printf "отброшено %s пакетов (%s байт)\n", $1, $2; found=1} END {if (!found) print "счётчик недоступен"}'
    done
    if [[ -f $STATS_FILE ]]; then
        python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); print("Последнее обновление:", s["time"])' "$STATS_FILE"
    fi
    systemctl list-timers 'rkn-block-*' --no-pager 2>/dev/null || true
}

cmd_test() {
    [[ $# -eq 1 ]] || die "использование: rkn-block test <IP>"
    need_root
    local ip=$1 a=$SET_A4 b=$SET_B4
    [[ $ip == *:* ]] && { a=$SET_A6; b=$SET_B6; }
    if ipset -q test "$a" "$ip"; then
        echo "$ip: в allow-листе — не блокируется"
    elif ipset -q test "$b" "$ip"; then
        echo "$ip: БЛОКИРУЕТСЯ"
    else
        echo "$ip: не блокируется"
    fi
}

valid_net() {
    python3 - "$1" "$MIN_PREFIX_V4" "$MIN_PREFIX_V6" <<'PY'
import ipaddress, sys
try:
    n = ipaddress.ip_network(sys.argv[1], strict=False)
except ValueError:
    sys.exit("некорректный IP или подсеть")
if n.prefixlen < int(sys.argv[2] if n.version == 4 else sys.argv[3]):
    sys.exit("слишком широкая сеть")
print(n)
PY
}

cmd_ban() {
    [[ $# -eq 1 ]] || die "использование: rkn-block ban <IP или подсеть>"
    need_root
    load_config
    take_lock wait
    local net set=$SET_B4
    net=$(valid_net "$1") || exit 1
    [[ $net == *:* ]] && set=$SET_B6
    touch "$EXTRA_FILE"
    grep -qxF "$net" "$EXTRA_FILE" || printf '%s\n' "$net" >> "$EXTRA_FILE"
    ipset add -exist "$set" "$net"
    save_state
    info "$net заблокирован и добавлен в $EXTRA_FILE"
    if ipset -q test "${set/block/allow}" "${net%/*}"; then
        warn "$net пересекается с allow-листом — эти адреса всё равно будут пропускаться"
    fi
}

cmd_unban() {
    [[ $# -eq 1 ]] || die "использование: rkn-block unban <IP или подсеть>"
    need_root
    load_config
    take_lock wait
    local net set=$SET_B4
    net=$(valid_net "$1") || exit 1
    [[ $net == *:* ]] && set=$SET_B6
    if [[ -f $EXTRA_FILE ]]; then
        grep -vxF "$net" "$EXTRA_FILE" > "$EXTRA_FILE.tmp" || true
        chmod 0644 "$EXTRA_FILE.tmp"
        mv -f "$EXTRA_FILE.tmp" "$EXTRA_FILE"
    fi
    ipset del -exist "$set" "$net"
    save_state
    info "$net удалён из ручного списка"
    if ipset -q test "$set" "${net%/*}"; then
        warn "адрес всё ещё входит в скачанный список; чтобы пропускать его, добавьте в $ALLOW_FILE и выполните rkn-block update"
    fi
}

cmd_top() {
    need_root
    load_config
    [[ $LOG_DROPS == yes ]] || die "журнал выключен: задайте LOG_DROPS=yes в $CONF_FILE и выполните rkn-block ensure"
    journalctl -k --since "${1:--24h}" --no-pager -o cat --grep "$LOG_PREFIX" 2>/dev/null \
        | grep -oE 'SRC=[^ ]+' | cut -d= -f2 | sort | uniq -c | sort -rn | head -20
}

write_default_config() {
    mkdir -p "$CONF_DIR"
    chmod 0755 "$CONF_DIR"
    if [[ ! -f $CONF_FILE ]]; then
        cat > "$CONF_FILE" <<EOF
# Настройки rkn-block. После изменения: rkn-block update

# Источники: https-адреса или абсолютные пути к локальным файлам.
SOURCES=(
    "$LISTS_BASE/government_networks.list"
    "$LISTS_BASE/antiscanner.list"
    "$LISTS_BASE/skipa.list"
    "$EXTRA_FILE"
)

# Защита от испорченных списков: обновление отклоняется, прежние списки остаются.
MIN_PREFIX_V4=$MIN_PREFIX_V4
MIN_PREFIX_V6=$MIN_PREFIX_V6
MAX_V4_ADDRESSES=$MAX_V4_ADDRESSES
MAX_ENTRIES=$MAX_ENTRIES
MAX_SHRINK_PERCENT=$MAX_SHRINK_PERCENT
MAX_GROW_FACTOR=$MAX_GROW_FACTOR

# yes = журналировать отброшенные пакеты (journalctl -k), нужно для rkn-block top.
# После изменения: rkn-block ensure
LOG_DROPS=$LOG_DROPS

# yes = защищать и порты, опубликованные из Docker (-p), через цепочку DOCKER-USER.
# После изменения: rkn-block ensure
PROTECT_DOCKER=$PROTECT_DOCKER

DOWNLOAD_TIMEOUT=$DOWNLOAD_TIMEOUT
EOF
        chmod 0644 "$CONF_FILE"
    fi
    if [[ ! -f $ALLOW_FILE ]]; then
        cat > "$ALLOW_FILE" <<'EOF'
# Адреса и подсети, которые НИКОГДА не блокируются (по одному в строке).
# Впишите сюда свои постоянные IP для администрирования, мониторинг и т.п.
# Служебные сети, адреса сервера и текущие SSH-подключения добавляются автоматически.
EOF
        chmod 0644 "$ALLOW_FILE"
    fi
    if [[ ! -f $EXTRA_FILE ]]; then
        printf '# Ручной блок-лист (rkn-block ban / unban).\n' > "$EXTRA_FILE"
        chmod 0644 "$EXTRA_FILE"
    fi
}

install_hook() {
    if [[ -e $UFW_HOOK ]] && ! grep -qF "$HOOK_MARK" "$UFW_HOOK"; then
        # Штатный шаблон Ubuntu неисполняемый, UFW его не вызывает. Чужой исполняемый хук не трогаем.
        if [[ -x $UFW_HOOK ]]; then
            die "$UFW_HOOK уже используется. Добавьте в него вручную:
    start) $SELF_PATH hook-start || true ;;
    stop)  $SELF_PATH hook-stop  || true ;;"
        fi
        cp -p "$UFW_HOOK" "$UFW_HOOK_BACKUP"
    fi
    cat > "$UFW_HOOK" <<EOF
#!/bin/sh
$HOOK_MARK: UFW вызывает этот файл при start/stop/reload.
case "\$1" in
    start) [ -x $SELF_PATH ] && $SELF_PATH hook-start || true ;;
    stop)  [ -x $SELF_PATH ] && $SELF_PATH hook-stop || true ;;
esac
exit 0
EOF
    chmod 0755 "$UFW_HOOK"
}

remove_hook() {
    [[ -f $UFW_HOOK ]] && grep -qF "$HOOK_MARK" "$UFW_HOOK" || return 0
    if [[ -f $UFW_HOOK_BACKUP ]]; then
        mv -f "$UFW_HOOK_BACKUP" "$UFW_HOOK"
    else
        rm -f "$UFW_HOOK"
    fi
}

install_units() {
    local common='ProtectSystem=strict
ReadWritePaths=/var/lib/rkn-block /run
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes'
    cat > "$UNIT_DIR/rkn-block-update.service" <<EOF
[Unit]
Description=rkn-block: обновление списков подсетей
Wants=network-online.target
After=network-online.target ufw.service

[Service]
Type=oneshot
ExecStart=$SELF_PATH update
$common
EOF
    cat > "$UNIT_DIR/rkn-block-update.timer" <<'EOF'
[Unit]
Description=rkn-block: регулярное обновление списков

[Timer]
OnBootSec=3min
OnUnitActiveSec=12h
RandomizedDelaySec=15min

[Install]
WantedBy=timers.target
EOF
    cat > "$UNIT_DIR/rkn-block-ensure.service" <<EOF
[Unit]
Description=rkn-block: проверка, что блокировка подключена
After=ufw.service

[Service]
Type=oneshot
ExecStart=$SELF_PATH ensure
$common
EOF
    cat > "$UNIT_DIR/rkn-block-ensure.timer" <<'EOF'
[Unit]
Description=rkn-block: периодическая проверка правил

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
EOF
    # Docker создаёт DOCKER-USER при старте, уже после UFW. Подключаемся сразу после запуска
    # Docker, не дожидаясь таймера. Перезапуск Docker для этого не нужен.
    if systemctl cat docker.service >/dev/null 2>&1; then
        mkdir -p "$UNIT_DIR/docker.service.d"
        cat > "$UNIT_DIR/docker.service.d/rkn-block.conf" <<EOF
# rkn-block: подключить защиту к DOCKER-USER после запуска Docker
[Service]
ExecStartPost=-$SELF_PATH ensure
EOF
        chmod 0644 "$UNIT_DIR/docker.service.d/rkn-block.conf"
    fi
    systemctl daemon-reload
    systemctl enable --now rkn-block-update.timer rkn-block-ensure.timer >/dev/null
}

remove_units() {
    systemctl disable --now rkn-block-update.timer rkn-block-ensure.timer >/dev/null 2>&1 || true
    rm -f "$UNIT_DIR"/rkn-block-{update,ensure}.{service,timer} "$UNIT_DIR/docker.service.d/rkn-block.conf"
    rmdir "$UNIT_DIR/docker.service.d" 2>/dev/null || true
    systemctl daemon-reload
}

cmd_install() {
    need_root
    need_cmds ipset iptables ip6tables python3 curl ss ip flock systemctl ufw
    ufw status | grep -q '^Status: active' || die "UFW не запущен. rkn-block рассчитан на работающий UFW"
    grep -qs after.init /lib/ufw/ufw-init-functions /usr/lib/ufw/ufw-init-functions \
        || die "эта версия UFW не поддерживает /etc/ufw/after.init (нужен UFW 0.36+)"
    if iptables -w -S 2>/dev/null | grep -q SCANNERS-BLOCK; then
        warn "обнаружены правила rkn-guard (SCANNERS-BLOCK). Работать будет, но лучше удалить его: rkn-guard uninstall"
    fi

    local src
    src=$(readlink -f "$0")
    [[ $src == "$SELF_PATH" ]] || install -m 0755 "$src" "$SELF_PATH"
    write_default_config
    mkdir -p "$STATE_DIR"

    local peers
    peers=$(ssh_peers | tr '\n' ' ')
    if [[ -n $peers && -t 0 ]]; then
        info "Текущие SSH-подключения: $peers"
        read -r -p "Добавить эти IP в постоянный allow-лист? Имеет смысл только для статических IP [y/N]: " ans
        if [[ $ans == [yY]* ]]; then
            ssh_peers | while read -r p; do grep -qxF "$p" "$ALLOW_FILE" || printf '%s\n' "$p" >> "$ALLOW_FILE"; done
        fi
    fi

    info "Пробная проверка списков"
    "$SELF_PATH" update --dry-run

    install_hook
    "$SELF_PATH" update
    install_units

    if [[ -t 0 ]]; then
        echo
        echo "Блокировка включена. Текущая SSH-сессия не прервётся в любом случае."
        echo "Откройте НОВОЕ SSH-подключение в другом окне и проверьте сервисы (VPN, сайт)."
        local ans=""
        read -r -t "$CONFIRM_TIMEOUT" -p "Всё работает? Введите yes в течение $CONFIRM_TIMEOUT секунд, иначе изменения откатятся: " ans || true
        if [[ $ans != yes ]]; then
            echo
            warn "подтверждения нет — отключаю блокировку"
            remove_units
            remove_hook
            take_lock wait
            detach_all
            die "блокировка отключена. Конфиг остался в $CONF_DIR; повторить: rkn-block install"
        fi
    fi
    info "Установка завершена. Состояние: rkn-block status"
}

cmd_uninstall() {
    need_root
    local purge=0
    [[ ${1:-} == --purge ]] && purge=1
    remove_units
    remove_hook
    take_lock wait
    detach_all
    local s
    for s in "$SET_B4" "$SET_B6" "$SET_A4" "$SET_A6"; do ipset -q destroy "$s" || true; done
    rm -rf "$STATE_DIR"
    rm -f "$SELF_PATH"
    if ((purge)); then
        rm -rf "$CONF_DIR"
    else
        info "Настройки оставлены в $CONF_DIR (удалить вместе с ними: --purge)"
    fi
    info "rkn-block удалён"
}

usage() {
    cat <<EOF
rkn-block — блокировка подсетей сканеров (ipset + iptables, для серверов с UFW)

  install                 установить (скрипт копируется в $SELF_PATH)
  update [--force]        скачать, проверить и применить списки
  update --dry-run        только скачать и проверить, ничего не менять
  status                  состояние, число записей, счётчик отброшенных пакетов
  test <IP>               блокируется ли адрес
  ban <IP|CIDR>           заблокировать вручную (сохраняется в $EXTRA_FILE)
  unban <IP|CIDR>         убрать из ручного блок-листа
  top [период]            топ источников за период (по умолчанию -24h; нужен LOG_DROPS=yes)
  ensure                  переподключить правила, если что-то их сбросило
  uninstall [--purge]     удалить всё (с --purge — и настройки)

Файлы: $CONF_FILE, $ALLOW_FILE, $EXTRA_FILE
EOF
}

main() {
    local cmd=${1:-help}
    shift || true
    case $cmd in
        install) cmd_install "$@" ;;
        update) cmd_update "$@" ;;
        check) cmd_update --dry-run ;;
        ensure) cmd_ensure ;;
        hook-start) cmd_hook start ;;
        hook-stop) cmd_hook stop ;;
        status) cmd_status ;;
        test) cmd_test "$@" ;;
        ban) cmd_ban "$@" ;;
        unban) cmd_unban "$@" ;;
        top) cmd_top "$@" ;;
        uninstall) cmd_uninstall "$@" ;;
        help|-h|--help) usage ;;
        *) usage; exit 1 ;;
    esac
}

main "$@"
