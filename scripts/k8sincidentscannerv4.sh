#!/usr/bin/env bash

###############################################################################
# Kubernetes Incident Diagnostic Scanner v4
#
# READ-ONLY / NON-MUTATING KUBERNETES RESOURCE SCANNER.
# (Not "zero side effects": see the kubectl exec note below.)
#
# This script NEVER runs: apply, create, delete, patch, edit, replace,
# scale, rollout restart/undo, cordon, drain, uncordon, taint, label,
# annotate, or any command that changes cluster state. It only uses
# get / describe / logs / top / auth can-i / get --raw for Kubernetes
# resources -- no resource is ever created, modified, or deleted.
#
# EXEC CAVEAT: optionally (OFF by default, ENABLE_POD_NETWORK_TEST=1),
# it runs read-only `kubectl exec` diagnostics (hostname / resolv.conf /
# routes) against EXISTING pods. This does not modify any Kubernetes
# resource, but `kubectl exec` does start a process inside an existing
# container -- so this mode is diagnostic execution, not purely passive
# observation, and stays off by default for that reason.
#
# ENDPOINT PROBE CAVEAT: optionally (OFF by default, ENABLE_ENDPOINT_PROBE=1),
# it issues a single HTTP GET (never POST/PUT/PATCH/DELETE) via `kubectl
# exec` into each Service endpoint's OWN container, at its own loopback
# address. Same category of caveat as above: no Kubernetes object is ever
# created, modified or deleted, but a process is executed and a real
# request is made. Off by default; see section "ENDPOINT PROBE" below.
#
# F5 / EXTERNAL LB HOOK: optionally (F5_LOG_SOURCE and/or F5_LOG_HOOK), this
# scanner can fold findings from an EXTERNAL load balancer / WAF (e.g. F5
# BIG-IP) into the same report. This scanner has no direct access to any
# appliance outside Kubernetes, so this is a pluggable, opt-in hook: you
# point it at a log file/directory you already export, or at your own
# executable that prints log lines to stdout. The scanner only READS
# whatever that hook or file produces -- it never calls out to F5 itself,
# and does not execute anything against F5. See section "F5 / EXTERNAL
# LOAD BALANCER" below.
#
# LIVE LOG VIEWER: before the scan prompts, the script offers to just
# `kubectl logs -f` one chosen pod instead of running a scan at all. Same
# read-only category as every other `logs` call here -- it only reads a
# stream, changes nothing -- and it exits (no scan, no report) once you
# stop watching. See "LIVE LOG VIEWER" below.
#
# It requires NO public internet access -- only connectivity to your
# Kubernetes API server via the existing kubeconfig, and writes report
# files locally.
###############################################################################

set +e

# Startup banner, drawn once on the very first run only -- not repeated on
# every loop iteration below, and not repeated anywhere else in the script
# or its reports. Block-letter art with an orange -> yellow gradient on a
# color terminal; plain block letters when output is not a TTY.
print_first_run_banner() {
    local -A G=(
        [S]="█████/█    /█████/    █/█████"
        [H]="█   █/█   █/█████/█   █/█   █"
        [A]=" ███ /█   █/█████/█   █/█   █"
        [D]="████ /█   █/█   █/█   █/████ "
        [Y]="█   █/ █ █ /  █  /  █  /  █  "
        [G]=" ████/█    /█  ██/█   █/ ███ "
        [O]=" ███ /█   █/█   █/█   █/ ███ "
        [M]="█   █/██ ██/█ █ █/█   █/█   █"
        [_]="   /   /   /   /   "
    )
    local text="SHADY_GOMAA" colors=(202 208 208 214 220) r i ch line
    local -a rows
    local use_color=0
    [ -t 1 ] && use_color=1

    echo ""
    if [ "$use_color" -eq 1 ]; then
        printf '  \033[38;5;245mdeveloped by\033[0m\n\n'
    else
        printf '  developed by\n\n'
    fi
    for r in 0 1 2 3 4; do
        line=""
        for ((i=0; i<${#text}; i++)); do
            ch="${text:i:1}"
            IFS='/' read -ra rows <<< "${G[$ch]}"
            line+="${rows[r]} "
        done
        if [ "$use_color" -eq 1 ]; then
            printf '  \033[38;5;%sm%s\033[0m\n' "${colors[r]}" "$line"
        else
            printf '  %s\n' "$line"
        fi
    done
    echo ""
}

# Snapshot any non-interactive overrides ONCE, before the loop below. Each
# loop iteration resets its working variable to this snapshot rather than
# to whatever value the PREVIOUS iteration's interactive prompt produced --
# otherwise, from the second iteration onward, these would already be
# non-empty from the last run and every prompt would be silently skipped.
ORIG_LIVE_LOGS_POD="${LIVE_LOGS_POD:-}"
ORIG_SCAN_MINUTES="${SCAN_MINUTES:-}"
ORIG_SEARCH_VALUE="${SEARCH_VALUE:-}"
ORIG_SCAN_NAMESPACE="${SCAN_NAMESPACE:-}"
ORIG_SCAN_POD_SELECTION="${SCAN_POD_SELECTION:-}"
ORIG_REPORT_DIR="${REPORT_DIR:-}"

FIRST_RUN=1

# The script returns to the first question after every scan. That is only
# wanted in an interactive terminal. When stdin is not a terminal (cron, CI,
# `< /dev/null`) or RUN_ONCE=1 is set, the script exits after ONE run instead
# of re-running the same scan forever.
RUN_ONCE="${RUN_ONCE:-0}"
should_exit_after_run() { [ "$RUN_ONCE" = "1" ] || [ ! -t 0 ]; }

# The whole script body runs inside this loop: after a scan (or a live-log
# session) finishes, execution falls through to "done" at the very bottom
# and loops back here -- no need to relaunch the script. Ctrl+C at any
# prompt exits normally (default SIGINT handling of `read`/the running
# command), which remains the way to actually quit.
while true; do

LIVE_LOGS_POD="$ORIG_LIVE_LOGS_POD"
SCAN_MINUTES="$ORIG_SCAN_MINUTES"
SEARCH_VALUE="$ORIG_SEARCH_VALUE"
SCAN_NAMESPACE="$ORIG_SCAN_NAMESPACE"
SCAN_POD_SELECTION="$ORIG_SCAN_POD_SELECTION"
REPORT_DIR="$ORIG_REPORT_DIR"

if [ "$FIRST_RUN" = "1" ]; then
    print_first_run_banner
    FIRST_RUN=0
fi

echo "============================================================"
echo " KUBERNETES INCIDENT DIAGNOSTIC SCANNER v4"
echo "============================================================"
echo ""

###############################################################################
# LIVE LOG VIEWER (optional, read-only, exits after use)
#
# Before running a full scan, offer a shortcut: just tail one pod's logs
# live (kubectl logs -f) instead of a full scan. Useful when you already
# know which pod is acting up and just want to watch it right now. This
# does not run the scan or produce a report -- it exits when you stop
# watching (Ctrl+C) or the log stream ends.
#
# Still strictly read-only: `kubectl logs -f` only reads a log stream,
# same category as every other `logs` call this scanner already makes --
# it changes nothing in the cluster.
###############################################################################

LIVE_LOGS_POD="${LIVE_LOGS_POD:-}"   # optional non-interactive "namespace/podname" override
WANT_LIVE_LOGS="n"

if [ -n "$LIVE_LOGS_POD" ]; then
    WANT_LIVE_LOGS="y"
elif [ -t 0 ]; then
    read -r -p "Do you want to watch LIVE LOGS of a pod right now, instead of running a scan? [y/N]: " LIVE_LOGS_CHOICE
    case "$LIVE_LOGS_CHOICE" in
        [Yy]*) WANT_LIVE_LOGS="y" ;;
        *) WANT_LIVE_LOGS="n" ;;
    esac
fi

if [ "$WANT_LIVE_LOGS" = "y" ]; then
    if [ -n "$LIVE_LOGS_POD" ]; then
        LIVE_NS="${LIVE_LOGS_POD%%/*}"
        LIVE_POD="${LIVE_LOGS_POD#*/}"
    else
        echo ""
        echo "Discovering namespaces..."
        LIVE_NS_DISCOVERY=$(kubectl get namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null | sort)
        if [ -z "$LIVE_NS_DISCOVERY" ]; then
            echo "Could not list namespaces (cluster not reachable, or kubectl unavailable)."
            echo "Continuing to the normal scan instead."
            WANT_LIVE_LOGS="n"
        else
            LIVE_NS_ARRAY=()
            while IFS= read -r live_ns; do
                [ -n "$live_ns" ] && LIVE_NS_ARRAY+=("$live_ns")
            done <<< "$LIVE_NS_DISCOVERY"
            echo ""
            for i in "${!LIVE_NS_ARRAY[@]}"; do
                printf "  %d. %s\n" "$((i+1))" "${LIVE_NS_ARRAY[$i]}"
            done
            echo ""
            read -r -p "Enter a namespace number [Enter to cancel]: " LIVE_NS_NUM
            case "$LIVE_NS_NUM" in
                ''|*[!0-9]*)
                    echo "No namespace selected -- continuing to the normal scan instead."
                    WANT_LIVE_LOGS="n"
                    ;;
                *)
                    LIVE_NS_IDX=$((LIVE_NS_NUM-1))
                    if [ "$LIVE_NS_IDX" -ge 0 ] && [ "$LIVE_NS_IDX" -lt "${#LIVE_NS_ARRAY[@]}" ]; then
                        LIVE_NS="${LIVE_NS_ARRAY[$LIVE_NS_IDX]}"
                    else
                        echo "Number out of range -- continuing to the normal scan instead."
                        WANT_LIVE_LOGS="n"
                    fi
                    ;;
            esac

            if [ "$WANT_LIVE_LOGS" = "y" ] && [ -n "${LIVE_NS:-}" ]; then
                echo ""
                echo "Discovering pods in namespace: $LIVE_NS ..."
                LIVE_POD_DISCOVERY=$(kubectl get pods -n "$LIVE_NS" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null | sort)
                if [ -z "$LIVE_POD_DISCOVERY" ]; then
                    echo "No pods found in namespace '$LIVE_NS'. Continuing to the normal scan instead."
                    WANT_LIVE_LOGS="n"
                else
                    LIVE_POD_ARRAY=()
                    while IFS= read -r live_p; do
                        [ -n "$live_p" ] && LIVE_POD_ARRAY+=("$live_p")
                    done <<< "$LIVE_POD_DISCOVERY"
                    echo ""
                    for i in "${!LIVE_POD_ARRAY[@]}"; do
                        printf "  %d. %s\n" "$((i+1))" "${LIVE_POD_ARRAY[$i]}"
                    done
                    echo ""
                    read -r -p "Enter the number of the pod to watch [Enter to cancel]: " LIVE_POD_NUM
                    case "$LIVE_POD_NUM" in
                        ''|*[!0-9]*)
                            echo "No pod selected -- continuing to the normal scan instead."
                            WANT_LIVE_LOGS="n"
                            ;;
                        *)
                            LIVE_IDX=$((LIVE_POD_NUM-1))
                            if [ "$LIVE_IDX" -ge 0 ] && [ "$LIVE_IDX" -lt "${#LIVE_POD_ARRAY[@]}" ]; then
                                LIVE_POD="${LIVE_POD_ARRAY[$LIVE_IDX]}"
                            else
                                echo "Invalid selection -- continuing to the normal scan instead."
                                WANT_LIVE_LOGS="n"
                            fi
                            ;;
                    esac
                fi
            fi
        fi
    fi
fi

if [ "$WANT_LIVE_LOGS" = "y" ] && [ -n "${LIVE_NS:-}" ] && [ -n "${LIVE_POD:-}" ]; then
    echo ""
    echo "============================================================"
    echo " LIVE LOGS: $LIVE_NS/$LIVE_POD  (read-only: kubectl logs -f)"
    echo " Press Ctrl+C to stop watching. No scan will run."
    echo "============================================================"
    echo ""
    # NOTE: the trap does not call exit -- exit inside a trap always
    # terminates the whole process, not just this loop iteration, which
    # would defeat "return to the first question" below. It just prints
    # and returns; kubectl logs -f itself receives the same SIGINT and
    # terminates on its own, so execution naturally continues to the
    # "continue" statement right after either way (Ctrl+C or a natural
    # end of the log stream).
    trap 'echo ""; echo "Stopped watching logs."' INT
    kubectl logs -f -n "$LIVE_NS" "$LIVE_POD" --all-containers --timestamps
    trap - INT
    echo ""
    echo "Log stream ended (pod may have restarted or the container exited)."
    if should_exit_after_run; then exit 0; fi
    echo "Returning to the first question..."
    continue
fi

###############################################################################
# 0. INTERACTIVE INPUT: SCAN WINDOW + SEARCH FILTER
###############################################################################

DEFAULT_MINUTES=1440   # 24 hours

echo "------------------------------------------------------------"
echo "1. SCAN TIME WINDOW"
echo "------------------------------------------------------------"
echo "Examples: 15=15min  60=1h  180=3h  720=12h  1440=24h"
echo ""

# Allow non-interactive override via env vars (for cron / CI use)
SCAN_MINUTES="${SCAN_MINUTES:-}"
SEARCH_VALUE="${SEARCH_VALUE:-}"

if [ -t 0 ] && [ -z "$SCAN_MINUTES" ]; then
    read -r -p "Enter minutes back to scan [default: ${DEFAULT_MINUTES}]: " INPUT_MINUTES
    SCAN_MINUTES="${INPUT_MINUTES:-$DEFAULT_MINUTES}"
elif [ -z "$SCAN_MINUTES" ]; then
    SCAN_MINUTES="$DEFAULT_MINUTES"
fi

# Validate: must be a positive integer, else fall back to default
case "$SCAN_MINUTES" in
    ''|*[!0-9]*) SCAN_MINUTES="$DEFAULT_MINUTES" ;;
esac
[ "$SCAN_MINUTES" -lt 1 ] 2>/dev/null && SCAN_MINUTES="$DEFAULT_MINUTES"

echo ""
echo "------------------------------------------------------------"
echo "2. SCAN SCOPE"
echo "------------------------------------------------------------"

# Two-level picker: namespace first (with an ALL NAMESPACES option), then
# -- only if a specific namespace was chosen -- pods within that one
# namespace (with an ALL PODS option). Choosing ALL NAMESPACES scans
# everything and skips the pod-narrowing step entirely, same as the
# companion log-search tool's scope picker.
#
# Non-interactive overrides (for cron / CI use):
#   SCAN_NAMESPACE       "all"/"full", or a literal namespace name
#   SCAN_POD_SELECTION   "all", or a comma-separated list of literal pod
#                         names within that namespace (ignored when
#                         SCAN_NAMESPACE is "all"/"full")
SCAN_NAMESPACE="${SCAN_NAMESPACE:-}"
SCAN_POD_SELECTION="${SCAN_POD_SELECTION:-}"
SELECTED_NS=""
SELECTED_PODS=""
SCOPE_MODE="FULL"

if [ -n "$SCAN_NAMESPACE" ] && [ "$SCAN_NAMESPACE" != "all" ] && [ "$SCAN_NAMESPACE" != "full" ]; then
    SELECTED_NS="$SCAN_NAMESPACE"
    echo "Namespace scope set via SCAN_NAMESPACE env var: $SELECTED_NS"
elif [ -n "$SCAN_NAMESPACE" ]; then
    echo "Namespace scope set via SCAN_NAMESPACE env var: ALL NAMESPACES"
elif [ -t 0 ]; then
    echo "Discovering namespaces..."
    NS_DISCOVERY=$(kubectl get namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null | sort)
    if [ -z "$NS_DISCOVERY" ]; then
        echo "Could not list namespaces (cluster not reachable yet, or kubectl unavailable)."
        echo "Defaulting to FULL SCAN -- connectivity will be verified in the next step."
    else
        NS_ARRAY=()
        while IFS= read -r ns_name; do
            [ -n "$ns_name" ] && NS_ARRAY+=("$ns_name")
        done <<< "$NS_DISCOVERY"
        echo ""
        echo "  0. ALL NAMESPACES"
        for i in "${!NS_ARRAY[@]}"; do
            printf "  %d. %s\n" "$((i+1))" "${NS_ARRAY[$i]}"
        done
        echo ""
        read -r -p "Enter a namespace number [default: 0 = ALL NAMESPACES]: " NS_CHOICE
        if [ -n "$NS_CHOICE" ] && [ "$NS_CHOICE" != "0" ]; then
            case "$NS_CHOICE" in
                *[!0-9]*)
                    echo "Invalid selection -- defaulting to ALL NAMESPACES."
                    ;;
                *)
                    if [ "$NS_CHOICE" -ge 1 ] 2>/dev/null && [ "$NS_CHOICE" -le "${#NS_ARRAY[@]}" ] 2>/dev/null; then
                        SELECTED_NS="${NS_ARRAY[$((NS_CHOICE-1))]}"
                    else
                        echo "Number out of range -- defaulting to ALL NAMESPACES."
                    fi
                    ;;
            esac
        fi
    fi
fi

if [ -n "$SELECTED_NS" ]; then
    echo ""
    echo "------------------------------------------------------------"
    echo "2b. SELECT POD(S) IN NAMESPACE: $SELECTED_NS"
    echo "------------------------------------------------------------"

    if [ -n "$SCAN_POD_SELECTION" ] && [ "$SCAN_POD_SELECTION" != "all" ]; then
        SELECTED_PODS=$(echo "$SCAN_POD_SELECTION" | tr ',' ' ')
        SCOPE_MODE="NAMESPACE_SELECTED"
        echo "Pod scope set via SCAN_POD_SELECTION env var: $SELECTED_PODS"
    elif [ -n "$SCAN_POD_SELECTION" ]; then
        SCOPE_MODE="NAMESPACE_ALL_PODS"
        echo "Pod scope set via SCAN_POD_SELECTION env var: ALL PODS in $SELECTED_NS"
    elif [ -t 0 ]; then
        POD_DISCOVERY=$(kubectl get pods -n "$SELECTED_NS" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null | sort)
        if [ -z "$POD_DISCOVERY" ]; then
            echo "No pods found in namespace '$SELECTED_NS' (or cluster not reachable)."
            echo "Defaulting to ALL PODS in this namespace -- will simply find nothing to scan if truly empty."
            SCOPE_MODE="NAMESPACE_ALL_PODS"
        else
            POD_ARRAY=()
            while IFS= read -r pod_entry; do
                [ -n "$pod_entry" ] && POD_ARRAY+=("$pod_entry")
            done <<< "$POD_DISCOVERY"
            echo ""
            echo "  0. ALL PODS in $SELECTED_NS"
            for i in "${!POD_ARRAY[@]}"; do
                printf "  %d. %s\n" "$((i+1))" "${POD_ARRAY[$i]}"
            done
            echo ""
            read -r -p "Enter pod number(s), comma-separated, or 0 for all [default: 0 = ALL PODS]: " POD_SELECTION
            if [ -n "$POD_SELECTION" ] && [ "$POD_SELECTION" != "0" ]; then
                PICKED=""
                IFS=',' read -ra POD_NUMS <<< "$POD_SELECTION"
                for n in "${POD_NUMS[@]}"; do
                    n=$(echo "$n" | tr -d '[:space:]')
                    case "$n" in ''|*[!0-9]*) continue ;; esac
                    idx=$((n-1))
                    if [ "$idx" -ge 0 ] && [ "$idx" -lt "${#POD_ARRAY[@]}" ]; then
                        PICKED="$PICKED ${POD_ARRAY[$idx]}"
                    fi
                done
                PICKED=$(echo "$PICKED" | sed 's/^ *//')
                if [ -n "$PICKED" ]; then
                    SELECTED_PODS="$PICKED"
                    SCOPE_MODE="NAMESPACE_SELECTED"
                else
                    echo "No valid pod numbers recognized -- defaulting to ALL PODS in $SELECTED_NS."
                    SCOPE_MODE="NAMESPACE_ALL_PODS"
                fi
            else
                SCOPE_MODE="NAMESPACE_ALL_PODS"
            fi
        fi
    else
        SCOPE_MODE="NAMESPACE_ALL_PODS"
    fi
fi

echo ""
echo "------------------------------------------------------------"
echo "3. TARGETED SEARCH (optional)"
echo "------------------------------------------------------------"
echo "Enter an ID / IP / error string to search for (transaction ID,"
echo "request ID, correlation ID, user ID, IP, exception name, etc)."
echo "Leave empty for a full cluster scan."
echo ""

if [ -t 0 ] && [ -z "$SEARCH_VALUE" ]; then
    read -r -p "Enter search value [default: FULL SCAN]: " INPUT_SEARCH
    SEARCH_VALUE="$INPUT_SEARCH"
fi

# Treat the search value as literal DATA only. Never evaluate it.
SEARCH_MODE="FULL_SCAN"
if [ -n "$SEARCH_VALUE" ]; then
    SEARCH_MODE="TARGETED"
fi

SCAN_END_EPOCH=$(date +%s)
SCAN_START_EPOCH=$((SCAN_END_EPOCH - SCAN_MINUTES*60))
SCAN_START_HUMAN=$(date -d "@$SCAN_START_EPOCH" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -r "$SCAN_START_EPOCH" '+%Y-%m-%d %H:%M:%S')
SCAN_END_HUMAN=$(date -d "@$SCAN_END_EPOCH" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date -r "$SCAN_END_EPOCH" '+%Y-%m-%d %H:%M:%S')

# Shared scope description, used everywhere (Confirm Scan, FINAL SUMMARY,
# HTML report, README) so the three scope modes are described consistently
# in exactly one place.
scope_description() {
    case "$SCOPE_MODE" in
        NAMESPACE_ALL_PODS) echo "Namespace '$SELECTED_NS', ALL pods" ;;
        NAMESPACE_SELECTED) echo "Namespace '$SELECTED_NS', pod(s):$SELECTED_PODS" ;;
        *) echo "Full infrastructure (all namespaces, all pods)" ;;
    esac
}

echo ""
echo "------------------------------------------------------------"
echo "4. CONFIRM SCAN"
echo "------------------------------------------------------------"
echo "Time range : last ${SCAN_MINUTES} minutes (${SCAN_START_HUMAN} -> ${SCAN_END_HUMAN})"
echo "Scope      : $(scope_description)"
echo "Search     : ${SEARCH_VALUE:-<none, full scan>}"
echo "Mode       : ${SEARCH_MODE}"
echo ""
echo "kubectl exec diagnostics : DISABLED by default (ENABLE_POD_NETWORK_TEST=1 to enable)"
echo "Endpoint GET probes      : ${ENABLE_ENDPOINT_PROBE:-0} (0=disabled by default; ENABLE_ENDPOINT_PROBE=1 to enable, GET only)"
echo "F5/external LB hook      : $([ -n "${F5_LOG_SOURCE:-}${F5_LOG_HOOK:-}" ] && echo "configured" || echo "not configured (F5_LOG_SOURCE / F5_LOG_HOOK)")"
echo "Kubernetes modifications : NONE (never executed by this script)"
echo ""

###############################################################################
# CONFIGURATION
###############################################################################

REPORT_DIR="${REPORT_DIR:-k8s-incident-report-$(date +%Y%m%d-%H%M%S)}"
ENABLE_POD_NETWORK_TEST="${ENABLE_POD_NETWORK_TEST:-0}"   # off by default, per safety review
ENABLE_LOG_SCAN="${ENABLE_LOG_SCAN:-1}"

# --- Endpoint probe (opt-in, off by default) ---
# Issues a live GET, via kubectl exec into each endpoint pod's OWN
# container, at 127.0.0.1:<containerPort><PROBE_PATH>. Confirms the app
# actually answers -- not just that Kubernetes reports it Ready. Still
# read-only for Kubernetes objects (no create/patch/delete); it does run
# a process inside the container and makes a real GET request, so it is
# off by default, same as ENABLE_POD_NETWORK_TEST.
ENABLE_ENDPOINT_PROBE="${ENABLE_ENDPOINT_PROBE:-0}"
PROBE_PATH="${PROBE_PATH:-/}"
PROBE_TIMEOUT="${PROBE_TIMEOUT:-3}"
PROBE_PORT_OVERRIDE="${PROBE_PORT_OVERRIDE:-}"     # force a port instead of using declared containerPorts

# --- F5 / external load balancer log hook (pluggable, off unless set) ---
# F5_LOG_SOURCE: a file or directory of already-exported F5 logs, read as-is.
# F5_LOG_HOOK:   an executable this scanner runs and captures stdout from
#                (e.g. your own wrapper around an iControl REST GET call,
#                an rsync/scp of the latest log, a Splunk/ELK query). It
#                must be read-only on the F5 side by design of the hook
#                itself -- this scanner does not and cannot enforce that,
#                it only consumes stdout.
F5_LOG_SOURCE="${F5_LOG_SOURCE:-}"
F5_LOG_HOOK="${F5_LOG_HOOK:-}"
F5_BLOCK_PATTERN="${F5_BLOCK_PATTERN:-blocking_exception_reason|support_id|violation_rating|asm.*block|tcp_rst|reset by peer|connection refused by big-?ip|no members available|pool.*monitor.*down|node.*monitor.*down|exceeded.*connection limit|irule.*(drop|reject)}"

# --- Slowness / performance triage thresholds (all opt-out via env override,
# all read-only checks -- see "API LATENCY", "ETCD HEALTH", node oversub in
# section 2, and HPA STATUS in section 4). These give circumstantial
# evidence toward common infra-side causes of "the app works but is slow";
# they cannot diagnose a slow application request path itself (that needs
# tracing/APM this scanner has no access to) -- see Coverage Limitations.
API_LATENCY_WARN_MS="${API_LATENCY_WARN_MS:-1000}"
API_LATENCY_CRIT_MS="${API_LATENCY_CRIT_MS:-3000}"
NODE_CPU_WARN_PCT="${NODE_CPU_WARN_PCT:-75}"
NODE_CPU_CRIT_PCT="${NODE_CPU_CRIT_PCT:-90}"
NODE_MEM_WARN_PCT="${NODE_MEM_WARN_PCT:-75}"
NODE_MEM_CRIT_PCT="${NODE_MEM_CRIT_PCT:-90}"
POD_CPU_WARN_PCT="${POD_CPU_WARN_PCT:-80}"
POD_CPU_CRIT_PCT="${POD_CPU_CRIT_PCT:-95}"
POD_MEM_WARN_PCT="${POD_MEM_WARN_PCT:-80}"
POD_MEM_CRIT_PCT="${POD_MEM_CRIT_PCT:-95}"

# Millisecond-resolution wall clock without shelling out to `date` (whose
# %N nanosecond format is GNU-only and silently breaks on macOS/BSD date).
# $EPOCHREALTIME is a bash 5+ builtin (seconds.microseconds); falls back to
# whole-second resolution on older bash, which is coarser but still
# functional for flagging multi-second API latency.
now_ms() {
    if [ -n "${EPOCHREALTIME:-}" ]; then
        local sec="${EPOCHREALTIME%%.*}" frac="${EPOCHREALTIME#*.}"
        echo $(( sec * 1000 + 10#${frac:0:3} ))
    else
        echo $(( $(date +%s) * 1000 ))
    fi
}

# Many Kubernetes-ecosystem components (metrics-server, controller-manager,
# kube-proxy, etc.) log via klog, whose line format is a level letter
# (I=Info, W=Warning, E=Error, F=Fatal) immediately after the timestamp,
# e.g. "...Z I0925 21:06:17.664085 1 tlsconfig.go:243] ...". Info-level
# klog lines routinely contain words like "certificate", "failed", or
# "timeout" as part of completely normal startup/retry chatter (e.g.
# "Failed probe ... no metrics to serve" while a cache warms up), which
# would otherwise false-positive against ERROR_PATTERN below. This filter
# excludes only the Info level (I) -- Warning/Error/Fatal (W/E/F) klog
# lines are never excluded. Set NOISE_EXCLUDE_PATTERN="" to disable.
#
# NOTE: the default value below is assigned via an isset-check + plain
# assignment rather than "${NOISE_EXCLUDE_PATTERN:-default}", because
# bash's ${VAR:-default} scanner treats ANY literal "}" inside default
# (even from a harmless-looking {4} regex interval) as closing the
# expansion early, silently truncating the pattern. This form also
# correctly treats an explicit NOISE_EXCLUDE_PATTERN="" as "disabled"
# rather than "unset" (":-" would have overridden an empty string back
# to the default, which is not what "set it empty to disable" should do).
if [ -z "${NOISE_EXCLUDE_PATTERN+set}" ]; then
    NOISE_EXCLUDE_PATTERN='^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z[[:space:]]+I[0-9]{4}[[:space:]]'
fi

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

mkdir -p "$REPORT_DIR/logs" "$REPORT_DIR/data" "$REPORT_DIR/raw"
REPORT="$REPORT_DIR/kubernetes-health-report.txt"
ERROR_REPORT="$REPORT_DIR/errors-and-warnings.txt"
FIX_REPORT="$REPORT_DIR/recommended-fixes.txt"
MATCH_REPORT="$REPORT_DIR/search-matches.txt"
TIMELINE_FILE="$REPORT_DIR/data/timeline.tsv"
FACTS_FILE="$REPORT_DIR/data/facts.tsv"
ROOTCAUSE_REPORT="$REPORT_DIR/root-cause-analysis.txt"
HTML_REPORT="$REPORT_DIR/index.html"
SEARCH_STATS_FILE="$REPORT_DIR/data/search-stats.tsv"   # occurrences per resource
PROBE_REPORT="$REPORT_DIR/endpoint-probe-results.txt"
PROBE_TSV="$REPORT_DIR/data/probe-results.tsv"
F5_REPORT="$REPORT_DIR/data/f5-external.log"

: > "$REPORT"; : > "$ERROR_REPORT"; : > "$FIX_REPORT"; : > "$MATCH_REPORT"; : > "$TIMELINE_FILE"; : > "$FACTS_FILE"; : > "$ROOTCAUSE_REPORT"; : > "$SEARCH_STATS_FILE"; : > "$PROBE_REPORT"; : > "$PROBE_TSV"; : > "$F5_REPORT"

###############################################################################
# CORRELATION ENGINE: record structured facts as we find them, then at the
# end of the scan chain them into ranked root-cause candidates. This is
# heuristic/evidence-based correlation, not proof of causation -- the HTML
# report labels it "candidate", never "confirmed".
#
# Fact record (tab-separated):
#   RANK  CATEGORY  NAMESPACE  RESOURCE  OWNER  DETAIL  TIMESTAMP
#
# RANK = how "upstream" this fact typically is (lower = more likely root
# cause; higher = more likely a downstream symptom of something else):
#   10 CONTROL_PLANE   20 NODE   30 DNS   35 REDIS   38 SECURITY
#   40 NO_ENDPOINTS    45 OOM    50 RESTART   55 PENDING_SCHEDULING/PENDING_CONTAINER_ERROR/FAILED
#   60 LOG_ERROR       70 HAPROXY_5XX (almost always a symptom, not a cause)
#
# OWNER values map to a team in owner_label(): infra, network, developer,
# security, or a combined "X-or-Y" when the scanner can't tell which side
# owns the fix from API/log evidence alone.
###############################################################################
record_fact() {
    # $1 rank  $2 category  $3 namespace  $4 resource  $5 owner  $6 detail  $7 timestamp(optional)
    local ts="${7:-$(date '+%Y-%m-%d %H:%M:%S')}"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" "$ts" >> "$FACTS_FILE"
}

# Extract a leading RFC3339 timestamp from a `kubectl logs --timestamps` line,
# e.g. "2026-09-23T10:15:23.481123456Z app: connection refused". Falls back
# to empty (caller then uses "now") if the line has no such prefix.
extract_log_ts() {
    echo "$1" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}' | head -1 | tr 'T' ' '
}

# Redact credential-shaped strings before they land in the human-facing
# report (ERROR_REPORT excerpts, search-match context, catalog details,
# root-cause evidence). Scope is deliberately narrow: Bearer tokens,
# password=/secret=/api_key= fields, JWTs, and user:pass@host connection
# strings. We do NOT attempt broad PII redaction (emails, national IDs,
# phone numbers) -- that can't be reliably regex-detected without heavy
# false positives, AND this tool's own search feature is often used to
# find a customer's ID in context, so blanket PII redaction would defeat
# its purpose. Raw log files on disk are left untouched (kept for deep
# debugging); only the aggregated report views are redacted.
# Set REDACT_SECRETS=0 to disable.
REDACT_SECRETS="${REDACT_SECRETS:-1}"
redact() {
    if [ "$REDACT_SECRETS" = "0" ]; then
        cat
        return
    fi
    sed -E \
        -e 's/(Authorization:[[:space:]]*Bearer[[:space:]]+)[A-Za-z0-9._-]+/\1[REDACTED]/gI' \
        -e 's/([Aa][Pp][Ii][_-]?[Kk][Ee][Yy]["]?[[:space:]]*[:=][[:space:]]*["]?)[A-Za-z0-9._-]{8,}/\1[REDACTED]/g' \
        -e 's/([Pp]assword["]?[[:space:]]*[:=][[:space:]]*["]?)[^[:space:]"'"'"',]+/\1[REDACTED]/g' \
        -e 's/([Ss]ecret["]?[[:space:]]*[:=][[:space:]]*["]?)[A-Za-z0-9._-]{8,}/\1[REDACTED]/g' \
        -e 's/(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)/[REDACTED_JWT]/g' \
        -e 's#(://[A-Za-z0-9._-]+:)[^@/[:space:]]+(@)#\1[REDACTED]\2#g' \
        2>/dev/null
}

# Extract full multi-line exception/stack-trace blocks from a
# `kubectl logs --timestamps` file, instead of a flat grep dump that can
# sever a stack trace from the line that triggered it. A block starts at
# a line matching the error pattern and continues while later lines look
# like a continuation (indented, "at ...", "Caused by:", "...", a Python
# "File \"...\"" frame, or a bare "Traceback" header) -- ending at the
# first line that looks like a new, independent log entry. Blocks are
# delimited with ===BLOCK_START===/===BLOCK_END=== markers.
extract_incident_blocks() {
    # $1 = log file  $2 = ERE pattern identifying an error/exception start
    local f="$1" pat="$2"
    [ -f "$f" ] || return
    awk -v pat="$pat" '
        BEGIN { in_block=0 }
        {
            line=$0
            rest=line
            sub(/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z[ \t]*/, "", rest)
            # IGNORECASE is a gawk-only feature (mawk/POSIX awk ignore it
            # silently, breaking case-insensitive matching entirely) --
            # normalize to lowercase instead, since the ERROR_PATTERN terms
            # are already all-lowercase literals.
            is_match = (tolower(line) ~ pat)
            is_continuation = (rest ~ /^[ \t]/ || rest ~ /^(at |Caused by|\.\.\.|Traceback|File ")/)
            if (is_match && !in_block) {
                in_block=1
                print "===BLOCK_START==="
                print line
                next
            }
            if (in_block && is_continuation) {
                print line
                next
            }
            if (in_block) {
                print "===BLOCK_END==="
                in_block=0
                if (is_match) { in_block=1; print "===BLOCK_START==="; print line }
            }
        }
        END { if (in_block) print "===BLOCK_END===" }
    ' "$f"
}

# Turn the marker-delimited output of extract_incident_blocks() into
# readable "Incident #N" cards with first/last-observed timestamps.
format_incident_blocks() {
    # $1 = marker output (from extract_incident_blocks)  $2 = label (pod/container)
    local raw="$1" label="$2"
    echo "$raw" | awk -v label="$label" '
        BEGIN { n=0; inb=0 }
        /^===BLOCK_START===$/ { inb=1; n++; buf=""; first=""; last=""; next }
        /^===BLOCK_END===$/ {
            inb=0
            printf "\nIncident #%d  (%s)\n", n, label
            if (first!="") printf "  First observed : %s\n", first
            if (last!="")  printf "  Last observed  : %s\n", last
            printf "  ------------------------------------------------------------\n"
            printf "%s\n", buf
            next
        }
        inb {
            ts=$0
            sub(/[ \t].*/, "", ts)
            if (first=="") first=ts
            last=ts
            buf = buf $0 "\n"
        }
    '
}

CRITICAL=0; ERRORS=0; WARNINGS=0; INFO=0; MATCHES=0
REDIS_STATUS="NOT DETECTED"
REDIS_STATUS_RANK=0
CONTROL_PLANE_STATUS="UNKNOWN"

# Redis health is reported as a ranked state, not a single overwritable
# string, so a later "healthy" pod doesn't quietly downgrade an earlier
# "investigation required" finding for a different Redis pod. Higher
# rank always wins:
#   1 DETECTED / UNVERIFIED           (name-only match, not confirmed Redis)
#   2 DETECTED / HEALTH EVIDENCE GOOD (confirmed Redis, running+ready, no errors)
#   3 DETECTED / INVESTIGATION REQUIRED (confirmed Redis, errors/restarts/OOM)
#   4 DETECTED / NO READY ENDPOINTS   (confirmed Redis, not Ready / no endpoints)
set_redis_status() {
    local rank="$1" label="$2"
    if [ "$rank" -gt "$REDIS_STATUS_RANK" ]; then
        REDIS_STATUS_RANK="$rank"
        REDIS_STATUS="$label"
    fi
}

timestamp() { date '+%Y-%m-%d %H:%M:%S'; }

section() { echo ""; echo "===================================================================="; echo "$1"; echo "===================================================================="; echo ""; }

log()      { echo "[$(timestamp)] $1" >> "$REPORT"; }
info()     { INFO=$((INFO+1)); echo -e "${CYAN}[INFO]${NC} $1"; echo "[INFO] $1" >> "$REPORT"; }
warn()     { WARNINGS=$((WARNINGS+1)); echo -e "${YELLOW}[WARNING]${NC} $1"; echo "[WARNING] $1" >> "$REPORT"; echo "[WARNING] $1" >> "$ERROR_REPORT"; echo -e "$(date -u +%H:%M:%S)\tWARNING\t$1" >> "$TIMELINE_FILE"; }
error()    { ERRORS=$((ERRORS+1)); echo -e "${RED}[ERROR]${NC} $1"; echo "[ERROR] $1" >> "$REPORT"; echo "[ERROR] $1" >> "$ERROR_REPORT"; echo -e "$(date -u +%H:%M:%S)\tERROR\t$1" >> "$TIMELINE_FILE"; }
critical() { CRITICAL=$((CRITICAL+1)); echo -e "${RED}[CRITICAL]${NC} $1"; echo "[CRITICAL] $1" >> "$REPORT"; echo "[CRITICAL] $1" >> "$ERROR_REPORT"; echo -e "$(date -u +%H:%M:%S)\tCRITICAL\t$1" >> "$TIMELINE_FILE"; }
fix()      { echo "$1" >> "$FIX_REPORT"; }

command_exists() { command -v "$1" >/dev/null 2>&1; }

# Safe literal search (no eval, no shell interpretation of user input).
# Tracks not just "which files matched" but occurrence counts and the
# affected resource, so the summary can report "27 occurrences across 3
# pods in 2 namespaces" instead of a misleading "3 files matched".
search_context() {
    # $1 = file to search, $2 = label for match report (e.g. "current logs: ns/pod/container")
    local f="$1" label="$2" occ
    [ -z "$SEARCH_VALUE" ] && return
    [ -f "$f" ] || return
    occ=$(grep -F -c -- "$SEARCH_VALUE" "$f" 2>/dev/null)
    if [ -n "$occ" ] && [ "$occ" -gt 0 ] 2>/dev/null; then
        MATCHES=$((MATCHES+1))
        printf '%s\t%s\n' "$occ" "$label" >> "$SEARCH_STATS_FILE"
        {
            echo ""
            echo "============================================================"
            echo "MATCH: $label  (occurrences in this source: $occ)"
            echo "File:  $f"
            echo "============================================================"
            grep -F -B 20 -A 40 -- "$SEARCH_VALUE" "$f" 2>/dev/null | redact
        } >> "$MATCH_REPORT"
    fi
}

# Terminal highlight of the search keyword (black text on yellow background).
# Reads stdin, writes stdout. Literal (non-regex) match -- same semantics as
# the grep -F search itself -- and the term is passed via the environment so
# awk never interprets backslashes in it. Falls back to a plain pass-through
# when there is no search value or stdout is not a terminal, so piped/
# redirected output never gets escape codes in it.
highlight_term() {
    if [ -z "$SEARCH_VALUE" ] || [ ! -t 1 ]; then
        cat
        return
    fi
    HL_TERM="$SEARCH_VALUE" awk '
        BEGIN { term = ENVIRON["HL_TERM"]; tlen = length(term); on = "\033[30;43m"; off = "\033[0m" }
        {
            line = $0; out = ""
            if (tlen == 0) { print line; next }
            while ((i = index(line, term)) > 0) {
                out = out substr(line, 1, i-1) on substr(line, i, tlen) off
                line = substr(line, i + tlen)
            }
            print out line
        }'
}

###############################################################################
# ENDPOINT PROBE (opt-in, OFF by default: ENABLE_ENDPOINT_PROBE=1)
#
# Issues a single HTTP GET, via `kubectl exec` into the *target pod's own
# container*, to 127.0.0.1:<containerPort><PROBE_PATH>. This confirms the
# app process inside that specific pod is actually accepting and answering
# requests -- not just that Kubernetes considers it Ready -- which is
# exactly the "1 of 3 pods is silently broken while the Service still
# looks healthy overall" scenario this tool targets.
#
# Still strictly non-mutating for Kubernetes: kubectl exec creates no
# object and changes no resource. It IS a live process execution inside
# the container (same category of caveat as ENABLE_POD_NETWORK_TEST), and
# it issues a real GET -- never POST/PUT/PATCH/DELETE -- so treat it the
# same as any health-check hitting that path. Point PROBE_PATH at a safe
# health/readiness endpoint if your root path is not side-effect-free.
#
# LIMITATION: this probes from inside the pod's own network namespace
# (loopback), not from a remote client -- it proves "the app answers
# locally", not cross-node reachability, Service routing, or
# NetworkPolicy behavior. A FAIL here alongside Ready=True is a strong
# signal the app itself (not just the readiness probe) is broken; a PASS
# here alongside Ready=False points at the readiness probe/selector
# instead.
###############################################################################
probe_one() {
    # $1 ns  $2 pod  $3 container  $4 port  $5 svc  $6 label(ready/not-ready)
    local ns="$1" pod="$2" container="$3" port="$4" svc="$5" label="$6"
    local url="http://127.0.0.1:${port}${PROBE_PATH}"
    local result code

    result=$(kubectl exec "$pod" -n "$ns" -c "$container" -- \
        sh -c "if command -v curl >/dev/null 2>&1; then curl -s -o /dev/null -w '%{http_code}' -m ${PROBE_TIMEOUT} --request GET '$url'; else echo NOCURL; fi" 2>&1)

    if [ "$result" = "NOCURL" ]; then
        echo "PROBE SKIP  $ns/$pod ($container:$port, $label, svc=$svc) -- curl not present in this container image" >> "$PROBE_REPORT"
        printf 'SKIP\t%s\t%s\t%s\t%s\t%s\tno curl in image\n' "$ns" "$pod/$container" "$port" "$svc" "$label" >> "$PROBE_TSV"
        return
    fi

    code=$(echo "$result" | tail -1 | tr -dc '0-9')

    if [ -z "$code" ]; then
        error "Probe FAILED: $ns/$pod ($container:$port, $label endpoint of svc $svc) -- no HTTP response (connection refused/timeout) at $url"
        record_fact 44 PROBE_FAIL "$ns" "$pod/$container" "developer-or-network" "GET $url returned no response ($label endpoint for svc $svc) -- app not answering on this port despite current k8s state"
        echo "PROBE FAIL  $ns/$pod ($container:$port, $label, svc=$svc) -- no response at $url" >> "$PROBE_REPORT"
        printf 'FAIL\t%s\t%s\t%s\t%s\t%s\tno response\n' "$ns" "$pod/$container" "$port" "$svc" "$label" >> "$PROBE_TSV"
    elif [ "$code" -ge 500 ] 2>/dev/null; then
        error "Probe FAILED: $ns/$pod ($container:$port, $label endpoint of svc $svc) -- HTTP $code at $url"
        record_fact 44 PROBE_FAIL "$ns" "$pod/$container" "developer" "GET $url returned HTTP $code ($label endpoint for svc $svc)"
        echo "PROBE FAIL  $ns/$pod ($container:$port, $label, svc=$svc) -- HTTP $code" >> "$PROBE_REPORT"
        printf 'FAIL\t%s\t%s\t%s\t%s\t%s\tHTTP %s\n' "$ns" "$pod/$container" "$port" "$svc" "$label" "$code" >> "$PROBE_TSV"
    elif [ "$code" -ge 400 ] 2>/dev/null; then
        warn "Probe WARN: $ns/$pod ($container:$port, $label endpoint of svc $svc) -- HTTP $code at $url"
        echo "PROBE WARN  $ns/$pod ($container:$port, $label, svc=$svc) -- HTTP $code" >> "$PROBE_REPORT"
        printf 'WARN\t%s\t%s\t%s\t%s\t%s\tHTTP %s\n' "$ns" "$pod/$container" "$port" "$svc" "$label" "$code" >> "$PROBE_TSV"
    else
        echo "PROBE OK    $ns/$pod ($container:$port, $label, svc=$svc) -- HTTP $code" >> "$PROBE_REPORT"
        printf 'OK\t%s\t%s\t%s\t%s\t%s\tHTTP %s\n' "$ns" "$pod/$container" "$port" "$svc" "$label" "$code" >> "$PROBE_TSV"
    fi
}

probe_service_endpoints() {
    # $1 ns  $2 svc  $3 rows: "addr\tready\tpodname" lines (from EndpointSlice)
    local ns="$1" svc="$2" rows="$3"
    [ "$ENABLE_ENDPOINT_PROBE" = "1" ] || return
    [ -z "$rows" ] && return
    echo "$rows" | awk -F'\t' '{print $1"|"$2"|"$3}' | while IFS='|' read -r addr ready podname; do
        [ -z "$podname" ] && continue
        local label="ready"; [ "$ready" != "true" ] && label="not-ready"
        local containers found=0
        containers=$(kubectl get pod "$podname" -n "$ns" -o jsonpath='{range .spec.containers[*]}{.name}{"\n"}{end}' 2>/dev/null)
        for c in $containers; do
            local cports
            if [ -n "$PROBE_PORT_OVERRIDE" ]; then
                cports="$PROBE_PORT_OVERRIDE"
            else
                cports=$(kubectl get pod "$podname" -n "$ns" -o jsonpath="{.spec.containers[?(@.name=='$c')].ports[*].containerPort}" 2>/dev/null)
            fi
            for p in $cports; do
                found=1
                probe_one "$ns" "$podname" "$c" "$p" "$svc" "$label"
            done
        done
        if [ "$found" -eq 0 ]; then
            echo "PROBE SKIP  $ns/$podname ($label, svc=$svc) -- no containerPort declared; set PROBE_PORT_OVERRIDE to force one" >> "$PROBE_REPORT"
            printf 'SKIP\t%s\t%s\t%s\t%s\t%s\tno containerPort declared\n' "$ns" "$podname/-" "-" "$svc" "$label" >> "$PROBE_TSV"
        fi
    done
}

###############################################################################
# PRECHECK
###############################################################################

section "PRECHECK"

if ! command_exists kubectl; then
    echo "ERROR: kubectl is not installed or not in PATH."
    if should_exit_after_run; then exit 1; fi
    echo "Returning to the first question -- fix this and try again, or Ctrl+C to exit."
    continue
fi

if ! kubectl cluster-info >/dev/null 2>&1; then
    critical "Cannot connect to Kubernetes API server."
    fix "Check kubeconfig: kubectl config current-context"
    fix "Check connectivity: kubectl cluster-info"
    echo "Cannot connect to the Kubernetes API. Nothing was changed."
    if should_exit_after_run; then exit 1; fi
    echo "Returning to the first question -- this may be transient; try again, or Ctrl+C to exit."
    continue
fi

CURRENT_CONTEXT=$(kubectl config current-context 2>/dev/null)
log "Context: $CURRENT_CONTEXT"
log "Scan window: last ${SCAN_MINUTES} minutes ($SCAN_START_HUMAN -> $SCAN_END_HUMAN)"
log "Search mode: $SEARCH_MODE (${SEARCH_VALUE:-none})"

kubectl version >> "$REPORT" 2>&1
kubectl cluster-info >> "$REPORT" 2>&1

###############################################################################
# 1. KUBERNETES CONTROL PLANE HEALTH (not just "kubectl get pods worked")
###############################################################################

section "1. KUBERNETES CONTROL PLANE"

API_T0=$(now_ms)
READYZ_OUT=$(kubectl get --raw='/readyz?verbose' 2>&1)
READYZ_RC=$?
API_T1=$(now_ms)
READYZ_LATENCY_MS=$((API_T1 - API_T0))
echo "$READYZ_OUT" >> "$REPORT"
if [ $READYZ_RC -eq 0 ] && echo "$READYZ_OUT" | grep -qi "^readyz check passed\|ok$" ; then
    READYZ_STATE="HEALTHY"
else
    READYZ_STATE="PROBLEM"
    error "Kubernetes /readyz reports a problem."
    fix "Check: kubectl get --raw='/readyz?verbose'"
fi

API_T0=$(now_ms)
LIVEZ_OUT=$(kubectl get --raw='/livez?verbose' 2>&1)
LIVEZ_RC=$?
API_T1=$(now_ms)
LIVEZ_LATENCY_MS=$((API_T1 - API_T0))
echo "$LIVEZ_OUT" >> "$REPORT"
if [ $LIVEZ_RC -eq 0 ] && echo "$LIVEZ_OUT" | grep -qi "^livez check passed\|ok$"; then
    LIVEZ_STATE="HEALTHY"
else
    LIVEZ_STATE="PROBLEM"
    error "Kubernetes /livez reports a problem."
    fix "Check: kubectl get --raw='/livez?verbose'"
fi

# --- API server latency self-check: this scanner's own kubectl calls are
# the measurement. A slow response here (control plane or etcd overloaded)
# cascades into every controller and every app that talks to the API, and
# is one of the most common infra-wide causes of "everything feels slow"
# with no single crashing pod to point at. This is a single-sample check,
# not a trend -- a one-off blip can false-positive; corroborate with the
# etcd health check below and repeat runs before concluding this is a
# root cause.
API_LATENCY_MS=$READYZ_LATENCY_MS
[ "$LIVEZ_LATENCY_MS" -gt "$API_LATENCY_MS" ] && API_LATENCY_MS=$LIVEZ_LATENCY_MS

if [ "$API_LATENCY_MS" -ge "$API_LATENCY_CRIT_MS" ]; then
    critical "API server response time is elevated: ${API_LATENCY_MS}ms (critical threshold: ${API_LATENCY_CRIT_MS}ms) -- may indicate an overloaded control plane or slow etcd, which can cascade into slowness across the whole cluster."
    record_fact 12 API_LATENCY "-" "$CURRENT_CONTEXT" "infra" "API server /readyz-or-livez response took ${API_LATENCY_MS}ms (>= ${API_LATENCY_CRIT_MS}ms critical threshold) -- single-sample reading; corroborate with etcd health and repeat runs before treating as confirmed root cause"
elif [ "$API_LATENCY_MS" -ge "$API_LATENCY_WARN_MS" ]; then
    warn "API server response time is somewhat elevated: ${API_LATENCY_MS}ms (warning threshold: ${API_LATENCY_WARN_MS}ms)."
    record_fact 12 API_LATENCY "-" "$CURRENT_CONTEXT" "infra" "API server /readyz-or-livez response took ${API_LATENCY_MS}ms (>= ${API_LATENCY_WARN_MS}ms warning threshold)"
else
    info "API server response time: ${API_LATENCY_MS}ms (healthy, below ${API_LATENCY_WARN_MS}ms)."
fi

# CoreDNS as part of control-plane-adjacent health (checked in detail later too)
COREDNS_READY=$(kubectl get pods -n kube-system -l k8s-app=kube-dns \
    -o jsonpath='{range .items[*]}{.status.phase}{" "}{end}' 2>/dev/null)
if echo "$COREDNS_READY" | grep -q "Running" ; then
    COREDNS_STATE="HEALTHY"
else
    COREDNS_STATE="UNKNOWN/PROBLEM"
    warn "CoreDNS pods not confirmed Running via label k8s-app=kube-dns."
fi

if [ "$READYZ_STATE" = "HEALTHY" ] && [ "$LIVEZ_STATE" = "HEALTHY" ]; then
    CONTROL_PLANE_STATUS="HEALTHY"
else
    CONTROL_PLANE_STATUS="INVESTIGATION REQUIRED"
    record_fact 10 CONTROL_PLANE "-" "$CURRENT_CONTEXT" "infra" "readyz=$READYZ_STATE livez=$LIVEZ_STATE"
fi

info "Control plane: readyz=$READYZ_STATE livez=$LIVEZ_STATE coredns=$COREDNS_STATE"

###############################################################################
# 1B. ETCD HEALTH (best-effort -- only visible on kubeadm-style clusters
# where etcd runs as a static pod in kube-system; managed clusters like
# EKS/GKE/AKS run etcd outside the cluster entirely and this section will
# correctly report "not detected" rather than a false negative).
#
# Slow etcd (disk fsync latency, leader churn) is a classic, high-signal,
# purely read-only-detectable cause of cluster-wide slowness: etcd itself
# logs explicit "slow fdatasync" / "took too long" warnings when this
# happens, well before it becomes an outright outage.
###############################################################################

section "1C. ETCD HEALTH (best-effort)"

ETCD_PODS=$(kubectl get pods -n kube-system -l component=etcd -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)
if [ -z "$ETCD_PODS" ]; then
    ETCD_PODS=$(kubectl get pods -n kube-system -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null | grep -E '^etcd(-|$)')
fi

ETCD_SLOW_PATTERN='slow fdatasync|took too long|apply request took|waiting for readindex|failed to send out heartbeat|elected leader|lost leader|slow request'
ETCD_MATCH_COUNT=0
ETCD_POD_COUNT=0

if [ -z "$ETCD_PODS" ]; then
    info "No etcd pod found in kube-system -- either this is a managed cluster (EKS/GKE/AKS) where etcd runs outside Kubernetes and is not visible here, or a non-standard etcd deployment. Not a failure of this check."
else
    for ETCD_POD in $ETCD_PODS; do
        ETCD_POD_COUNT=$((ETCD_POD_COUNT+1))
        ETCD_LOG_FILE="$REPORT_DIR/logs/etcd_${ETCD_POD}.log"
        kubectl logs "$ETCD_POD" -n kube-system --since="${SCAN_MINUTES}m" --timestamps > "$ETCD_LOG_FILE" 2>&1
        ETCD_MATCHES=$(grep -Ei "$ETCD_SLOW_PATTERN" "$ETCD_LOG_FILE" 2>/dev/null)
        if [ -n "$ETCD_MATCHES" ]; then
            THIS_COUNT=$(echo "$ETCD_MATCHES" | grep -c .)
            ETCD_MATCH_COUNT=$((ETCD_MATCH_COUNT + THIS_COUNT))
            error "etcd ($ETCD_POD): $THIS_COUNT slow-operation warning(s) in the last ${SCAN_MINUTES}m -- classic early signal of disk/latency-driven cluster-wide slowness."
            { echo ""; echo "ETCD SLOW: $ETCD_POD"; echo "$ETCD_MATCHES" | redact; } >> "$ERROR_REPORT"
            FIRST_ETCD_LINE=$(echo "$ETCD_MATCHES" | head -1 | cut -c1-200 | redact)
            record_fact 15 ETCD_SLOW "-" "$ETCD_POD" "infra" "$THIS_COUNT slow-operation warning(s) ($FIRST_ETCD_LINE) -- check disk I/O latency on the node hosting etcd" "$(extract_log_ts "$FIRST_ETCD_LINE")"
            fix "kubectl logs $ETCD_POD -n kube-system --since=${SCAN_MINUTES}m --timestamps | grep -Ei 'slow fdatasync|took too long'"
            fix "On the node hosting $ETCD_POD: check disk I/O latency (iostat/fio), since etcd fsyncs every write"
        fi
        search_context "$ETCD_LOG_FILE" "etcd: $ETCD_POD"
    done
    if [ "$ETCD_MATCH_COUNT" -eq 0 ]; then
        info "etcd: $ETCD_POD_COUNT pod(s) checked, no slow-operation warnings in the last ${SCAN_MINUTES}m."
    fi
fi

###############################################################################
# 2. NODES
###############################################################################

section "2. NODE HEALTH"

kubectl get nodes -o wide >> "$REPORT" 2>&1
kubectl get nodes -o wide > "$REPORT_DIR/data/nodes.txt" 2>&1

if kubectl top nodes >/dev/null 2>&1; then
    kubectl top nodes >> "$REPORT" 2>&1
else
    warn "kubectl top nodes unavailable (Metrics Server may not be installed)."
    fix "Check: kubectl get pods -n kube-system | grep metrics"
fi

NODE_LIST=$(kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')

# --- Kubernetes quantity parsing for the oversubscription check below.
# Deliberately approximate (decimal M/G treated ~= binary Mi/Gi) -- this is
# a triage signal ("is this node roughly oversubscribed?"), not a billing
# calculation, and exact byte-precision doesn't change the conclusion.
cpu_to_millicores() {
    # Kubernetes CPU quantity -> integer millicores. "500m" -> 500, "2" -> 2000,
    # "0.5" -> 500. Anything unparseable (or empty) -> 0 rather than an
    # arithmetic error, so one odd value can never abort the scan section.
    local v="$1"
    [ -z "$v" ] && { echo 0; return; }
    awk -v q="$v" 'BEGIN {
        if (q ~ /^[0-9]+m$/)                { sub(/m$/, "", q); printf "%d", q; exit }
        if (q ~ /^[0-9]+(\.[0-9]+)?$/)      { printf "%d", q * 1000; exit }
        print 0
    }'
}
mem_to_mi() {
    # Kubernetes memory quantity -> integer MiB. Handles binary (Ki/Mi/Gi/Ti)
    # and decimal (k/M/G/T) suffixes, fractions ("1.5Gi"), and bare bytes.
    # Anything unparseable (or empty) -> 0 rather than an arithmetic error.
    local v="$1"
    [ -z "$v" ] && { echo 0; return; }
    awk -v q="$v" 'BEGIN {
        if (match(q, /^[0-9]+(\.[0-9]+)?/) == 0) { print 0; exit }
        n = substr(q, 1, RLENGTH) + 0
        u = substr(q, RLENGTH + 1)
        if      (u == "Ki") m = n / 1024
        else if (u == "Mi") m = n
        else if (u == "Gi") m = n * 1024
        else if (u == "Ti") m = n * 1024 * 1024
        else if (u == "k")  m = n * 1000 / 1048576
        else if (u == "M")  m = n * 1000000 / 1048576
        else if (u == "G")  m = n * 1000000000 / 1048576
        else if (u == "T")  m = n * 1000000000000 / 1048576
        else if (u == "")   m = n / 1048576
        else { print 0; exit }
        printf "%d", m
    }'
}

for NODE in $NODE_LIST; do
    NODE_DESC_FILE=$(mktemp)
    kubectl describe node "$NODE" > "$NODE_DESC_FILE" 2>&1
    cat "$NODE_DESC_FILE" >> "$REPORT"
    search_context "$NODE_DESC_FILE" "node describe: $NODE"
    rm -f "$NODE_DESC_FILE"

    COND=$(kubectl get node "$NODE" -o jsonpath='{range .status.conditions[*]}{.type}={.status}{" "}{end}' 2>/dev/null)
    IPS=$(kubectl get node "$NODE" -o jsonpath='{range .status.addresses[*]}{.type}={.address}{" "}{end}' 2>/dev/null)
    echo "NODE $NODE  IPs: $IPS  Conditions: $COND" >> "$REPORT"

    echo "$COND" | grep -q "Ready=False"          && { critical "Node $NODE is NOT Ready. ($IPS)"; record_fact 20 NODE_NOT_READY "-" "$NODE" "infra" "Ready=False ($IPS)"; }
    echo "$COND" | grep -q "MemoryPressure=True"  && { error "Node $NODE has MemoryPressure. ($IPS)"; record_fact 20 NODE_PRESSURE "-" "$NODE" "infra" "MemoryPressure ($IPS)"; }
    echo "$COND" | grep -q "DiskPressure=True"    && { error "Node $NODE has DiskPressure. ($IPS)"; record_fact 20 NODE_PRESSURE "-" "$NODE" "infra" "DiskPressure ($IPS)"; }
    echo "$COND" | grep -q "PIDPressure=True"     && { error "Node $NODE has PIDPressure. ($IPS)"; record_fact 20 NODE_PRESSURE "-" "$NODE" "infra" "PIDPressure ($IPS)"; }
    echo "$COND" | grep -q "NetworkUnavailable=True" && { error "Node $NODE reports NetworkUnavailable. ($IPS)"; record_fact 20 NODE_NETWORK "-" "$NODE" "network" "NetworkUnavailable ($IPS)"; }

    # --- Node oversubscription: requested vs. allocatable. A node running
    # near its allocatable CPU/memory from REQUESTS alone (regardless of
    # actual live usage) is a classic, purely-declarative cause of
    # scheduling delays, CPU contention, and "everything on this node
    # feels slow" -- and it's invisible to `kubectl top`, which only shows
    # current usage, not how tightly packed the node's declared requests
    # are.
    ALLOC_CPU_RAW=$(kubectl get node "$NODE" -o jsonpath='{.status.allocatable.cpu}' 2>/dev/null)
    ALLOC_MEM_RAW=$(kubectl get node "$NODE" -o jsonpath='{.status.allocatable.memory}' 2>/dev/null)
    ALLOC_CPU_M=$(cpu_to_millicores "$ALLOC_CPU_RAW")
    ALLOC_MEM_MI=$(mem_to_mi "$ALLOC_MEM_RAW")

    REQ_CPU_TOTAL_M=0
    REQ_MEM_TOTAL_MI=0
    # NOTE: fields are joined with "|" and read with IFS='|', NOT tab. Tab is
    # an IFS *whitespace* character, so consecutive tabs collapse: a container
    # with a memory request but no CPU request ("\t8Mi") would have its memory
    # value shifted into the CPU variable and crash the arithmetic below.
    # "|" is non-whitespace, so an empty field stays empty.
    NODE_POD_REQUESTS=$(kubectl get pods -A --field-selector spec.nodeName="$NODE" \
        -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.resources.requests.cpu}{"|"}{.resources.requests.memory}{"\n"}{end}{end}' 2>/dev/null)
    while IFS='|' read -r c_req m_req; do
        [ -z "$c_req" ] && [ -z "$m_req" ] && continue
        REQ_CPU_TOTAL_M=$((REQ_CPU_TOTAL_M + $(cpu_to_millicores "$c_req")))
        REQ_MEM_TOTAL_MI=$((REQ_MEM_TOTAL_MI + $(mem_to_mi "$m_req")))
    done <<< "$NODE_POD_REQUESTS"

    if [ "$ALLOC_CPU_M" -gt 0 ] 2>/dev/null; then
        CPU_PCT=$(( REQ_CPU_TOTAL_M * 100 / ALLOC_CPU_M ))
    else
        CPU_PCT=0
    fi
    if [ "$ALLOC_MEM_MI" -gt 0 ] 2>/dev/null; then
        MEM_PCT=$(( REQ_MEM_TOTAL_MI * 100 / ALLOC_MEM_MI ))
    else
        MEM_PCT=0
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$NODE" "$REQ_CPU_TOTAL_M" "$ALLOC_CPU_M" "$CPU_PCT" "$REQ_MEM_TOTAL_MI" "$ALLOC_MEM_MI" "$MEM_PCT" >> "$REPORT_DIR/data/node-oversubscription.tsv"

    if [ "$CPU_PCT" -ge "$NODE_CPU_CRIT_PCT" ] 2>/dev/null || [ "$MEM_PCT" -ge "$NODE_MEM_CRIT_PCT" ] 2>/dev/null; then
        error "Node $NODE is oversubscribed by REQUESTS: CPU ${CPU_PCT}% (${REQ_CPU_TOTAL_M}m/${ALLOC_CPU_M}m), Memory ${MEM_PCT}% (${REQ_MEM_TOTAL_MI}Mi/${ALLOC_MEM_MI}Mi) of allocatable -- little scheduling headroom; likely contributor to CPU contention/slowness for pods here, even if kubectl top shows moderate live usage."
        record_fact 22 NODE_OVERSUBSCRIBED "-" "$NODE" "infra-or-developer" "Requested CPU ${CPU_PCT}% / Memory ${MEM_PCT}% of allocatable -- from declared resource requests, not live usage; reduce requests or add node capacity"
        fix "kubectl describe node $NODE   # see 'Allocated resources' section"
        fix "kubectl get pods -A --field-selector spec.nodeName=$NODE -o wide"
    elif [ "$CPU_PCT" -ge "$NODE_CPU_WARN_PCT" ] 2>/dev/null || [ "$MEM_PCT" -ge "$NODE_MEM_WARN_PCT" ] 2>/dev/null; then
        warn "Node $NODE requests are getting tight: CPU ${CPU_PCT}%, Memory ${MEM_PCT}% of allocatable."
        record_fact 22 NODE_OVERSUBSCRIBED "-" "$NODE" "infra-or-developer" "Requested CPU ${CPU_PCT}% / Memory ${MEM_PCT}% of allocatable -- approaching capacity"
    fi
done

fix "Node OS-level history (kubelet/kernel/containerd journal for the last ${SCAN_MINUTES} min)"
fix "cannot be retrieved via the Kubernetes API alone. If needed, on the node itself run:"
fix "  journalctl -u kubelet --since \"${SCAN_MINUTES} minutes ago\""

###############################################################################
# 3. EVENTS -- Kubernetes Event retention is cluster-controlled, NOT tied to
# our scan window. We fetch whatever is currently retained, then separately
# report how many of those fall inside the requested window vs. outside it,
# so the HTML never implies "no events" means "nothing happened".
###############################################################################

section "3. CLUSTER EVENTS"

kubectl get events -A --sort-by=.lastTimestamp > "$REPORT_DIR/data/all-events.txt" 2>&1
cat "$REPORT_DIR/data/all-events.txt" >> "$REPORT"
search_context "$REPORT_DIR/data/all-events.txt" "cluster events"

kubectl get events -A --field-selector type=Warning --sort-by=.lastTimestamp \
    > "$REPORT_DIR/data/warning-events.txt" 2>&1
cat "$REPORT_DIR/data/warning-events.txt" >> "$REPORT"

# Machine-parsable copy with lastTimestamp, used to compute how many of the
# currently-retained events actually fall inside [SCAN_START, SCAN_END].
kubectl get events -A -o jsonpath='{range .items[*]}{.lastTimestamp}{"\t"}{.type}{"\t"}{.involvedObject.namespace}{"\t"}{.involvedObject.name}{"\t"}{.reason}{"\t"}{.message}{"\n"}{end}' \
    > "$REPORT_DIR/data/events_raw.tsv" 2>/dev/null

SCAN_START_UTC=$(date -u -d "@$SCAN_START_EPOCH" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -r "$SCAN_START_EPOCH" '+%Y-%m-%dT%H:%M:%SZ')
SCAN_END_UTC=$(date -u -d "@$SCAN_END_EPOCH" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -r "$SCAN_END_EPOCH" '+%Y-%m-%dT%H:%M:%SZ')

TOTAL_RETAINED_EVENTS=$(wc -l < "$REPORT_DIR/data/events_raw.tsv" 2>/dev/null | tr -d ' ')
TOTAL_RETAINED_EVENTS=${TOTAL_RETAINED_EVENTS:-0}
EVENTS_IN_WINDOW=$(awk -F'\t' -v s="$SCAN_START_UTC" -v e="$SCAN_END_UTC" '$1!="" && $1>=s && $1<=e' "$REPORT_DIR/data/events_raw.tsv" 2>/dev/null | wc -l | tr -d ' ')
EVENTS_IN_WINDOW=${EVENTS_IN_WINDOW:-0}

# When a single namespace was selected, only that namespace's events (plus
# cluster-level events with no namespace, e.g. node events) are listed.
awk -F'\t' -v s="$SCAN_START_UTC" -v e="$SCAN_END_UTC" -v sel="$SELECTED_NS" -v OFS='\t' \
    '$1!="" && $1>=s && $1<=e && $2=="Warning" && (sel=="" || $3=="" || $3==sel)' \
    "$REPORT_DIR/data/events_raw.tsv" > "$REPORT_DIR/data/warning-events-in-window.tsv" 2>/dev/null
WARN_EVT_COUNT=$(wc -l < "$REPORT_DIR/data/warning-events-in-window.tsv" 2>/dev/null | tr -d ' ')
WARN_EVT_COUNT=${WARN_EVT_COUNT:-0}

if [ "$WARN_EVT_COUNT" -gt 0 ] 2>/dev/null; then
    warn "Found $WARN_EVT_COUNT Warning event(s) inside the requested ${SCAN_MINUTES}-minute window${SELECTED_NS:+ for namespace $SELECTED_NS (plus cluster-level events)} (of $TOTAL_RETAINED_EVENTS total events currently retained by the API server)."
    echo "    Most recent Warning events (newest first, max 15; full list in errors-and-warnings.txt):"
    sort -t$'\t' -k1,1r "$REPORT_DIR/data/warning-events-in-window.tsv" | head -15 | awk -F'\t' '{
        ts=$1; sub(/^[0-9-]+T/, "", ts); sub(/Z$/, "", ts)
        msg=$6; if (length(msg) > 160) msg=substr(msg, 1, 157) "..."
        printf "    %s  %s/%s  [%s] %s\n", ts, ($3=="" ? "-" : $3), $4, $5, msg }' | redact
    {
        echo ""
        echo "WARNING EVENTS IN WINDOW (${WARN_EVT_COUNT}), newest first:"
        sort -t$'\t' -k1,1r "$REPORT_DIR/data/warning-events-in-window.tsv" | awk -F'\t' '{
            printf "  %s  %s/%s  [%s] %s\n", $1, ($3=="" ? "-" : $3), $4, $5, $6 }' | redact
    } >> "$ERROR_REPORT"
fi

info "Events: $EVENTS_IN_WINDOW of $TOTAL_RETAINED_EVENTS currently-retained events fall inside the requested window ($SCAN_START_UTC -> $SCAN_END_UTC UTC). Kubernetes Event retention is set by the cluster, not by this scanner -- older events may already be gone, so a low count here does not prove nothing happened."

###############################################################################
# 4. NAMESPACE / WORKLOAD SCAN
###############################################################################

# --- Pod CPU/memory usage snapshot, fetched ONCE cluster-wide here (not
# per-pod in the loop below) to avoid one extra kubectl call per pod on a
# large cluster. Cross-referenced against each pod's own declared
# requests/limits during the per-pod loop below -- a raw "340Mi" number is
# meaningless without knowing whether that's near, at, or nowhere close to
# what the pod is allowed to use. Gracefully skipped if Metrics Server
# isn't installed (same condition the existing section 7 top-nodes/pods
# checks already handle).
POD_METRICS_FILE="$REPORT_DIR/data/pod-metrics-raw.tsv"
POD_METRICS_AVAILABLE=0
if kubectl top pods -A --no-headers > "$POD_METRICS_FILE" 2>/dev/null && [ -s "$POD_METRICS_FILE" ]; then
    POD_METRICS_AVAILABLE=1
else
    : > "$POD_METRICS_FILE"
    warn "kubectl top pods unavailable (Metrics Server may not be installed) -- per-pod CPU/memory usage will not be included in this report."
    fix "Check: kubectl get pods -n kube-system | grep metrics"
fi

# When scope is SELECTED (specific pods chosen), only namespaces that
# contain at least one selected pod are visited, and within each such
# namespace only the selected pods get the deep per-pod scan (describe,
# container status, restarts, OOM check, log scan). Deployment/
# StatefulSet/Job/CronJob/Service checks still run for the WHOLE
# namespace the pod lives in, not just the selected pod's own owner --
# this is a deliberate choice: it gives real context (e.g. "is the
# Service routing to this pod healthy?") at negligible extra cost,
# without needing full ownerReference resolution up front.
selected_pods_in_ns() {
    # SELECTED_PODS is already scoped to the single chosen namespace
    # (SELECTED_NS) by construction with the namespace-first picker, so
    # this no longer needs a namespace argument or any "ns/pod" splitting.
    echo "$SELECTED_PODS" | tr ' ' '\n'
}

case "$SCOPE_MODE" in
    NAMESPACE_ALL_PODS)
        NAMESPACE_LIST="$SELECTED_NS"
        info "Scan scope restricted to namespace: $SELECTED_NS (all pods)"
        ;;
    NAMESPACE_SELECTED)
        NAMESPACE_LIST="$SELECTED_NS"
        info "Scan scope restricted to namespace: $SELECTED_NS, pod(s): $SELECTED_PODS"
        ;;
    *)
        NAMESPACE_LIST=$(kubectl get namespaces -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
        ;;
esac

REDIS_FOUND=0

for NS in $NAMESPACE_LIST; do
    section "NAMESPACE: $NS"

    kubectl get all -n "$NS" -o wide >> "$REPORT" 2>&1

    # Workloads (Deployments + StatefulSets) with desired>0 and ZERO ready
    # replicas are complete outages of that workload -> CRITICAL. If EVERY
    # workload in the namespace is in that state it is a namespace outage.
    NS_WL_TOTAL=0; NS_WL_DOWN=0

    # --- Deployments ---
    DEPLOYMENTS=$(kubectl get deployment -n "$NS" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)
    for D in $DEPLOYMENTS; do
        DESIRED=$(kubectl get deployment "$D" -n "$NS" -o jsonpath='{.spec.replicas}' 2>/dev/null)
        READY=$(kubectl get deployment "$D" -n "$NS" -o jsonpath='{.status.readyReplicas}' 2>/dev/null)
        READY=${READY:-0}
        NS_WL_TOTAL=$((NS_WL_TOTAL+1))
        if [ "$READY" != "$DESIRED" ]; then
            if [ "$READY" = "0" ] && [ "${DESIRED:-0}" -gt 0 ] 2>/dev/null; then
                NS_WL_DOWN=$((NS_WL_DOWN+1))
                critical "Deployment $NS/$D is DOWN: 0 of $DESIRED replicas ready (complete outage of this workload)."
            else
                error "Deployment $NS/$D READY=$READY DESIRED=$DESIRED."
            fi
            fix "kubectl describe deployment $D -n $NS"
        fi
    done

    # --- StatefulSets: same ready/desired check as Deployments. Important
    # for Redis/Kafka/DB-style workloads where kubectl get all's raw dump
    # alone doesn't surface a mismatch as a finding. ---
    STATEFULSETS=$(kubectl get statefulset -n "$NS" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)
    for SS in $STATEFULSETS; do
        SS_DESIRED=$(kubectl get statefulset "$SS" -n "$NS" -o jsonpath='{.spec.replicas}' 2>/dev/null)
        SS_READY=$(kubectl get statefulset "$SS" -n "$NS" -o jsonpath='{.status.readyReplicas}' 2>/dev/null)
        SS_READY=${SS_READY:-0}
        NS_WL_TOTAL=$((NS_WL_TOTAL+1))
        if [ "$SS_READY" != "$SS_DESIRED" ]; then
            if [ "$SS_READY" = "0" ] && [ "${SS_DESIRED:-0}" -gt 0 ] 2>/dev/null; then
                NS_WL_DOWN=$((NS_WL_DOWN+1))
                critical "StatefulSet $NS/$SS is DOWN: 0 of $SS_DESIRED replicas ready (complete outage of this workload)."
            else
                error "StatefulSet $NS/$SS READY=$SS_READY DESIRED=$SS_DESIRED."
            fi
            fix "kubectl describe statefulset $SS -n $NS"
            record_fact 55 STATEFULSET_NOT_READY "$NS" "$SS" "infra-or-developer" "StatefulSet $SS: $SS_READY/$SS_DESIRED replicas ready"
        fi
    done

    if [ "$NS_WL_TOTAL" -gt 0 ] && [ "$NS_WL_DOWN" -eq "$NS_WL_TOTAL" ]; then
        critical "Namespace $NS: ALL $NS_WL_TOTAL workload(s) (Deployments/StatefulSets) have zero ready replicas -- complete namespace outage, not a partial degradation."
    fi

    # --- HPA: a Deployment/StatefulSet can look perfectly healthy (all
    # desired replicas Ready) while still being the reason an app "works
    # but is slow" -- too few replicas for current load, autoscaler maxed
    # out, or the HPA unable to read metrics at all. None of that shows up
    # in the ready-vs-desired check above, since "desired" here is set by
    # the HPA itself, not a fixed spec value. ---
    HPA_LIST=$(kubectl get hpa -n "$NS" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)
    for HPA in $HPA_LIST; do
        HPA_CUR=$(kubectl get hpa "$HPA" -n "$NS" -o jsonpath='{.status.currentReplicas}' 2>/dev/null)
        HPA_MIN=$(kubectl get hpa "$HPA" -n "$NS" -o jsonpath='{.spec.minReplicas}' 2>/dev/null)
        HPA_MAX=$(kubectl get hpa "$HPA" -n "$NS" -o jsonpath='{.spec.maxReplicas}' 2>/dev/null)
        HPA_TARGET=$(kubectl get hpa "$HPA" -n "$NS" -o jsonpath='{.spec.scaleTargetRef.name}' 2>/dev/null)
        HPA_SCALING_ACTIVE=$(kubectl get hpa "$HPA" -n "$NS" -o jsonpath='{range .status.conditions[?(@.type=="ScalingActive")]}{.status}{end}' 2>/dev/null)

        echo "HPA $NS/$HPA  target=$HPA_TARGET current=$HPA_CUR min=$HPA_MIN max=$HPA_MAX ScalingActive=$HPA_SCALING_ACTIVE" >> "$REPORT"

        if [ "$HPA_SCALING_ACTIVE" = "False" ]; then
            error "HPA $NS/$HPA (target: $HPA_TARGET) has ScalingActive=False -- it cannot read the metrics it needs to scale at all. If load is currently high, this workload will NOT scale up, which will feel like slowness/timeouts under load."
            fix "kubectl describe hpa $HPA -n $NS   # check the exact reason under Conditions"
            fix "kubectl get pods -n kube-system -l k8s-app=metrics-server   # confirm metrics-server itself is healthy"
            record_fact 43 HPA_INACTIVE "$NS" "$HPA" "infra-or-developer" "HPA for $HPA_TARGET has ScalingActive=False -- cannot obtain metrics to scale on; will not respond to load regardless of traffic"
        elif [ -n "$HPA_CUR" ] && [ -n "$HPA_MAX" ] && [ "$HPA_CUR" -ge "$HPA_MAX" ] 2>/dev/null; then
            warn "HPA $NS/$HPA (target: $HPA_TARGET) is at its maximum: $HPA_CUR/$HPA_MAX replicas. If it's still under load, this is a capacity ceiling, not a bug -- raise maxReplicas or node capacity."
            fix "kubectl describe hpa $HPA -n $NS"
            fix "kubectl top pods -n $NS -l app=$HPA_TARGET 2>/dev/null"
            record_fact 43 HPA_MAXED "$NS" "$HPA" "developer-or-infra" "HPA for $HPA_TARGET is maxed at $HPA_CUR/$HPA_MAX replicas -- likely under-provisioned for current load if traffic is still elevated"
        fi
    done

    # --- Jobs: flag any Job with failed pod attempts. `kubectl get all`
    # already lists Jobs in the raw dump, but doesn't turn a failure into
    # a structured finding -- this does. ---
    JOBS=$(kubectl get jobs -n "$NS" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)
    for J in $JOBS; do
        JOB_FAILED=$(kubectl get job "$J" -n "$NS" -o jsonpath='{.status.failed}' 2>/dev/null)
        if [ -n "$JOB_FAILED" ] && [ "$JOB_FAILED" -gt 0 ] 2>/dev/null; then
            error "Job $NS/$J has $JOB_FAILED failed pod attempt(s)."
            fix "kubectl describe job $J -n $NS"
            fix "kubectl logs -n $NS -l job-name=$J --all-containers --tail=200"
            record_fact 55 JOB_FAILED "$NS" "$J" "developer" "Job $J: $JOB_FAILED failed attempt(s)"
        fi
    done

    # --- CronJobs: flag one whose last scheduled run has no matching
    # successful completion (best-effort -- exact success tracking needs
    # the Job it spawned, which is already covered by the Jobs check above). ---
    CRONJOBS=$(kubectl get cronjobs -n "$NS" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)
    for CJ in $CRONJOBS; do
        CJ_SUSPENDED=$(kubectl get cronjob "$CJ" -n "$NS" -o jsonpath='{.spec.suspend}' 2>/dev/null)
        CJ_LAST_SCHEDULE=$(kubectl get cronjob "$CJ" -n "$NS" -o jsonpath='{.status.lastScheduleTime}' 2>/dev/null)
        CJ_LAST_SUCCESS=$(kubectl get cronjob "$CJ" -n "$NS" -o jsonpath='{.status.lastSuccessfulTime}' 2>/dev/null)
        if [ "$CJ_SUSPENDED" != "true" ] && [ -n "$CJ_LAST_SCHEDULE" ] && [ "$CJ_LAST_SCHEDULE" != "$CJ_LAST_SUCCESS" ]; then
            warn "CronJob $NS/$CJ last scheduled ($CJ_LAST_SCHEDULE) does not match last successful run ($CJ_LAST_SUCCESS:-none)."
            fix "kubectl describe cronjob $CJ -n $NS"
            fix "kubectl get jobs -n $NS -l app.kubernetes.io/created-by=$CJ 2>/dev/null; kubectl get jobs -n $NS | grep $CJ"
            record_fact 55 CRONJOB_UNCERTAIN "$NS" "$CJ" "developer" "Last scheduled=$CJ_LAST_SCHEDULE, last successful=${CJ_LAST_SUCCESS:-none} -- most recent run may have failed"
        fi
    done

    # --- Services + EndpointSlices (modern service-discovery path; falls
    # back to legacy Endpoints only if no EndpointSlice exists for a Service).
    # For each Service we resolve ready vs not-ready endpoint IPs AND the
    # pod that owns each one (via targetRef), so the report can show:
    #   Service -> ClusterIP -> [ready pod IPs] / [not-ready pod IPs]
    # instead of just a yes/no "has endpoints" flag. ---
    echo "Services:" >> "$REPORT"
    kubectl get svc -n "$NS" -o wide >> "$REPORT" 2>&1
    SERVICES=$(kubectl get svc -n "$NS" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)
    for SVC in $SERVICES; do
        kubectl describe svc "$SVC" -n "$NS" >> "$REPORT" 2>&1
        CLUSTER_IP=$(kubectl get svc "$SVC" -n "$NS" -o jsonpath='{.spec.clusterIP}' 2>/dev/null)

        SLICE_ROWS=$(kubectl get endpointslices -n "$NS" -l "kubernetes.io/service-name=$SVC" \
            -o jsonpath='{range .items[*]}{range .endpoints[*]}{.addresses[0]}{"\t"}{.conditions.ready}{"\t"}{.targetRef.name}{"\n"}{end}{end}' 2>/dev/null)

        if [ -z "$SLICE_ROWS" ]; then
            # Fallback: no EndpointSlice found (older cluster / CNI) -- use legacy Endpoints
            LEGACY_READY=$(kubectl get endpoints "$SVC" -n "$NS" -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null)
            LEGACY_NOTREADY=$(kubectl get endpoints "$SVC" -n "$NS" -o jsonpath='{.subsets[*].notReadyAddresses[*].ip}' 2>/dev/null)
            READY_LIST="$LEGACY_READY"
            NOTREADY_LIST="$LEGACY_NOTREADY"
        else
            READY_LIST=$(echo "$SLICE_ROWS" | awk -F'\t' '$2=="true"{ if ($3=="") printf "%s ", $1; else printf "%s(%s) ", $1, $3 }')
            NOTREADY_LIST=$(echo "$SLICE_ROWS" | awk -F'\t' '$2!="true"{ if ($3=="") printf "%s ", $1; else printf "%s(%s) ", $1, $3 }')
        fi

        # Optional active probe of every ready AND not-ready endpoint pod
        # for this Service (off by default -- see ENABLE_ENDPOINT_PROBE).
        # Only possible where we have per-endpoint pod names, i.e. the
        # EndpointSlice path; the legacy Endpoints fallback has IPs only.
        [ -n "$SLICE_ROWS" ] && probe_service_endpoints "$NS" "$SVC" "$SLICE_ROWS"

        echo "SERVICE $NS/$SVC  ClusterIP=$CLUSTER_IP  Ready=[$READY_LIST]  NotReady=[$NOTREADY_LIST]" >> "$REPORT"

        if [ -z "$READY_LIST" ] && [ -z "$NOTREADY_LIST" ]; then
            # Explain WHY there are no endpoints: compare the Service's selector
            # with the pods that actually carry those labels (read-only gets).
            SVC_SELECTOR=$(kubectl get svc "$SVC" -n "$NS" -o go-template='{{range $k,$v := .spec.selector}}{{$k}}={{$v}},{{end}}' 2>/dev/null)
            SVC_SELECTOR="${SVC_SELECTOR%,}"
            if [ -z "$SVC_SELECTOR" ]; then
                SEL_NOTE="the Service defines no selector (ExternalName or manually managed Endpoints)"
            else
                SEL_MATCH=$(kubectl get pods -n "$NS" -l "$SVC_SELECTOR" -o name 2>/dev/null | grep -c .)
                if [ "${SEL_MATCH:-0}" -eq 0 ] 2>/dev/null; then
                    SEL_NOTE="selector '$SVC_SELECTOR' matches ZERO pods in namespace $NS -- label/selector mismatch, so this Service can never route traffic regardless of pod health"
                else
                    SEL_NOTE="selector '$SVC_SELECTOR' matches $SEL_MATCH pod(s) but none are registered as endpoints -- they are likely not Running/Ready"
                fi
            fi
            error "Service $NS/$SVC (ClusterIP $CLUSTER_IP) has NO active endpoints (ready or not-ready) -- $SEL_NOTE."
            fix "kubectl describe svc $SVC -n $NS"
            fix "kubectl get svc $SVC -n $NS -o yaml   # confirm .spec.selector"
            fix "kubectl get endpointslices -n $NS -l kubernetes.io/service-name=$SVC"
            fix "kubectl get pods -n $NS --show-labels"
            record_fact 40 NO_ENDPOINTS "$NS" "$SVC" "developer-or-network" "Service $SVC ($CLUSTER_IP) has zero endpoints at all -- $SEL_NOTE"
        elif [ -z "$READY_LIST" ] && [ -n "$NOTREADY_LIST" ]; then
            error "Service $NS/$SVC (ClusterIP $CLUSTER_IP) has endpoints but NONE are Ready: $NOTREADY_LIST"
            fix "kubectl describe svc $SVC -n $NS"
            fix "kubectl get endpointslices -n $NS -l kubernetes.io/service-name=$SVC -o wide"
            record_fact 40 NO_ENDPOINTS "$NS" "$SVC" "developer-or-network" "Service $SVC ($CLUSTER_IP) has endpoints but all are NotReady: $NOTREADY_LIST -- pods exist but are failing readiness"
        elif [ -n "$NOTREADY_LIST" ]; then
            warn "Service $NS/$SVC (ClusterIP $CLUSTER_IP) is partially degraded -- ready: $READY_LIST | not-ready: $NOTREADY_LIST"
            record_fact 42 PARTIAL_NOT_READY "$NS" "$SVC" "developer" "Ready: $READY_LIST | NotReady: $NOTREADY_LIST -- some backing pods are failing readiness while others serve traffic"
        else
            info "Service $NS/$SVC ($CLUSTER_IP) all endpoints ready: $READY_LIST"
        fi

        # Save for the HTML "Service Topology" section
        printf '%s\t%s\t%s\t%s\t%s\n' "$NS" "$SVC" "$CLUSTER_IP" "$READY_LIST" "$NOTREADY_LIST" >> "$REPORT_DIR/data/service-topology.tsv"

        SVC_CONFIRMED_REDIS=0
        echo "$SVC" | grep -Eqi '(^|-)redis(-|$)' && SVC_CONFIRMED_REDIS=1
        SVC_PORT_LIST=$(kubectl get svc "$SVC" -n "$NS" -o jsonpath='{.spec.ports[*].port}' 2>/dev/null)
        echo "$SVC_PORT_LIST" | grep -Eq '(^|[^[:alnum:]_])(6379|6380)([^[:alnum:]_]|$)' && SVC_CONFIRMED_REDIS=1

        if [ $SVC_CONFIRMED_REDIS -eq 1 ]; then
            REDIS_FOUND=1
            if [ -z "$READY_LIST" ]; then
                set_redis_status 4 "DETECTED / NO READY ENDPOINTS (Service $SVC has none)"
            fi
        elif echo "$SVC" | grep -Eqi '(^|-)cache(-|$)|session-store'; then
            set_redis_status 1 "DETECTED / UNVERIFIED (Service name-only cache match, not confirmed Redis)"
        fi
    done

    kubectl get endpointslices -n "$NS" -o wide >> "$REPORT" 2>&1
    kubectl get ingress -n "$NS" -o wide >> "$REPORT" 2>&1
    kubectl get networkpolicy -n "$NS" >> "$REPORT" 2>&1

    # --- Pods ---
    POD_LIST=$(kubectl get pods -n "$NS" -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)
    if [ "$SCOPE_MODE" = "NAMESPACE_SELECTED" ]; then
        ALLOWED_PODS=$(selected_pods_in_ns)
        POD_LIST=$(echo "$POD_LIST" | while read -r p; do
            [ -z "$p" ] && continue
            echo "$ALLOWED_PODS" | grep -qx "$p" && echo "$p"
        done)
    fi

    for POD in $POD_LIST; do
        POD_STATUS=$(kubectl get pod "$POD" -n "$NS" -o jsonpath='{.status.phase}' 2>/dev/null)
        POD_IP=$(kubectl get pod "$POD" -n "$NS" -o jsonpath='{.status.podIP}' 2>/dev/null)
        NODE_NAME=$(kubectl get pod "$POD" -n "$NS" -o jsonpath='{.spec.nodeName}' 2>/dev/null)

        echo "" >> "$REPORT"
        echo "POD: $NS/$POD  STATUS=$POD_STATUS  IP=$POD_IP  NODE=$NODE_NAME" >> "$REPORT"
        POD_DESC_FILE=$(mktemp)
        kubectl describe pod "$POD" -n "$NS" > "$POD_DESC_FILE" 2>&1
        cat "$POD_DESC_FILE" >> "$REPORT"
        search_context "$POD_DESC_FILE" "pod describe: $NS/$POD"
        rm -f "$POD_DESC_FILE"

        case "$POD_STATUS" in
            Running|Succeeded) ;;
            Pending)
                # A "Pending" phase means two very different things that
                # need different fixes: the pod may still be unschedulable
                # (no node fits -- resources, taints, unbound PVC), or it
                # may already be scheduled to a node and stuck because a
                # container can't start (bad image, missing ConfigMap/
                # Secret). "kubectl top nodes"/"resourcequota" only helps
                # the first case; conflating them under one PENDING
                # category pointed the wrong commands at the wrong fix.
                WAITING_REASON=$(kubectl get pod "$POD" -n "$NS" -o jsonpath='{range .status.containerStatuses[*]}{.state.waiting.reason}{" "}{end}' 2>/dev/null | sed 's/[[:space:]]*$//')
                # The kubelet's own message names the exact missing ConfigMap /
                # Secret / key (or the failing image), e.g. 'configmap "x" not found'.
                WAITING_MESSAGE=$(kubectl get pod "$POD" -n "$NS" -o jsonpath='{range .status.containerStatuses[*]}{.state.waiting.message}{" | "}{end}' 2>/dev/null | tr '\t\n' '  ' | sed -e 's/[[:space:]|]*$//')
                if [ -n "$NODE_NAME" ] && echo "$WAITING_REASON" | grep -Eqi 'ImagePullBackOff|ErrImagePull|InvalidImageName|CreateContainerConfigError|CreateContainerError'; then
                    error "Pod $NS/$POD is Pending due to a container start error on node=$NODE_NAME (reason: $WAITING_REASON). Kubelet message: ${WAITING_MESSAGE:-<none reported>}"
                    fix "kubectl describe pod $POD -n $NS   # check Events for the exact image/config/secret error"
                    fix "kubectl get pod $POD -n $NS -o jsonpath='{.status.containerStatuses[*].state.waiting.message}'"
                    record_fact 55 PENDING_CONTAINER_ERROR "$NS" "$POD" "developer" "Pending on node=$NODE_NAME due to a container start error ($WAITING_REASON) -- kubelet message: ${WAITING_MESSAGE:-none reported} -- already scheduled fine; check the image reference, ConfigMap/Secret references, or registry credentials, not node capacity"
                else
                    error "Pod $NS/$POD is Pending. (node=${NODE_NAME:-<unscheduled>})"
                    fix "kubectl describe pod $POD -n $NS"
                    fix "kubectl top nodes"
                    fix "kubectl get resourcequota -n $NS"
                    record_fact 55 PENDING_SCHEDULING "$NS" "$POD" "infra-or-developer" "Pending, unscheduled or awaiting resources (node=${NODE_NAME:-none}) -- check node capacity, PVC binding, taints/affinity, or resource requests"
                fi
                ;;
            Failed)  error "Pod $NS/$POD is Failed. (node=$NODE_NAME)"; fix "kubectl logs $POD -n $NS --all-containers"; record_fact 55 FAILED "$NS" "$POD" "developer" "Pod Failed on node=$NODE_NAME" ;;
            Unknown) error "Pod $NS/$POD status is Unknown. (node=$NODE_NAME)"; record_fact 55 UNKNOWN "$NS" "$POD" "infra" "Pod status Unknown on node=$NODE_NAME -- possible node/kubelet issue" ;;
            *) [ -n "$POD_STATUS" ] && warn "Pod $NS/$POD has status $POD_STATUS." ;;
        esac

        READY_COND=$(kubectl get pod "$POD" -n "$NS" -o jsonpath='{range .status.conditions[?(@.type=="Ready")]}{.status}{end}' 2>/dev/null)
        if [ "$READY_COND" = "False" ] && [ "$POD_STATUS" = "Running" ]; then
            # Don't presume a readinessProbe exists and is "failing" -- a
            # Running-but-not-Ready pod is just as often a container that
            # hasn't finished starting, or one with NO readinessProbe at
            # all still cycling through restarts, as it is an actual probe
            # misconfiguration. Check for a defined readinessProbe on any
            # container before wording it either way.
            HAS_READINESS_PROBE=$(kubectl get pod "$POD" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.readinessProbe}{end}' 2>/dev/null)
            if [ -n "$HAS_READINESS_PROBE" ]; then
                warn "Pod $NS/$POD is Running but not Ready (a readinessProbe is defined and is failing)."
                record_fact 40 READINESS_FAIL "$NS" "$POD" "developer" "Running but Ready=False with a readinessProbe defined -- the probe itself is failing; pod is excluded from Service endpoints"
            else
                warn "Pod $NS/$POD is Running but not Ready (no readinessProbe is defined -- likely still starting up or cycling through restarts, not a probe failure)."
                record_fact 40 READINESS_FAIL "$NS" "$POD" "developer" "Running but Ready=False with NO readinessProbe defined -- check container startup/restart state (e.g. CrashLoopBackOff, OOM) rather than probe config; pod is excluded from Service endpoints"
            fi
        fi

        # --- CPU/memory usage vs. requests/limits. A raw "340Mi" or "120m"
        # number means nothing on its own -- this cross-references live
        # usage (from the cluster-wide metrics snapshot fetched before this
        # loop) against what the pod itself declares it's allowed to use.
        # Usage near/at the MEMORY limit is a leading indicator of an
        # impending OOMKill; usage near/at the CPU limit is a leading
        # indicator of CPU throttling (which this scanner otherwise cannot
        # detect directly -- see Coverage Limitations). A pod with NO
        # limit set is reported as such rather than skipped, since that is
        # itself worth knowing (unbounded CPU/memory is a stability risk
        # for its neighbors, not just itself).
        if [ "$POD_METRICS_AVAILABLE" = "1" ]; then
            POD_USAGE_LINE=$(awk -v ns="$NS" -v pod="$POD" '$1==ns && $2==pod {print $3"\t"$4}' "$POD_METRICS_FILE")
            if [ -n "$POD_USAGE_LINE" ]; then
                USAGE_CPU_RAW="${POD_USAGE_LINE%%$'\t'*}"
                USAGE_MEM_RAW="${POD_USAGE_LINE##*$'\t'}"
                USAGE_CPU_M=$(cpu_to_millicores "$USAGE_CPU_RAW")
                USAGE_MEM_MI=$(mem_to_mi "$USAGE_MEM_RAW")

                REQ_CPU_M=$(kubectl get pod "$POD" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.resources.requests.cpu}{" "}{end}' 2>/dev/null | tr ' ' '\n' | while read -r v; do cpu_to_millicores "$v"; done | awk '{s+=$1} END{print s+0}')
                LIM_CPU_M=$(kubectl get pod "$POD" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.resources.limits.cpu}{" "}{end}' 2>/dev/null | tr ' ' '\n' | while read -r v; do cpu_to_millicores "$v"; done | awk '{s+=$1} END{print s+0}')
                REQ_MEM_MI=$(kubectl get pod "$POD" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.resources.requests.memory}{" "}{end}' 2>/dev/null | tr ' ' '\n' | while read -r v; do mem_to_mi "$v"; done | awk '{s+=$1} END{print s+0}')
                LIM_MEM_MI=$(kubectl get pod "$POD" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.resources.limits.memory}{" "}{end}' 2>/dev/null | tr ' ' '\n' | while read -r v; do mem_to_mi "$v"; done | awk '{s+=$1} END{print s+0}')

                CPU_OF_LIMIT_PCT="n/a"; MEM_OF_LIMIT_PCT="n/a"
                [ "$LIM_CPU_M" -gt 0 ] 2>/dev/null && CPU_OF_LIMIT_PCT=$(( USAGE_CPU_M * 100 / LIM_CPU_M ))
                [ "$LIM_MEM_MI" -gt 0 ] 2>/dev/null && MEM_OF_LIMIT_PCT=$(( USAGE_MEM_MI * 100 / LIM_MEM_MI ))

                printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                    "$NS" "$POD" "$USAGE_CPU_M" "$REQ_CPU_M" "$LIM_CPU_M" "$CPU_OF_LIMIT_PCT" \
                    "$USAGE_MEM_MI" "$REQ_MEM_MI" "$LIM_MEM_MI" "$MEM_OF_LIMIT_PCT" >> "$REPORT_DIR/data/pod-resource-usage.tsv"

                if [ "$CPU_OF_LIMIT_PCT" != "n/a" ] && [ "$CPU_OF_LIMIT_PCT" -ge "$POD_CPU_CRIT_PCT" ] 2>/dev/null; then
                    error "Pod $NS/$POD CPU usage is ${CPU_OF_LIMIT_PCT}% of its limit (${USAGE_CPU_M}m/${LIM_CPU_M}m) -- at high risk of CPU throttling (which this scanner cannot directly observe), a common invisible cause of app-perceived slowness."
                    record_fact 47 POD_CPU_HIGH "$NS" "$POD" "developer-or-infra" "CPU usage ${CPU_OF_LIMIT_PCT}% of limit (${USAGE_CPU_M}m/${LIM_CPU_M}m) -- likely being throttled or about to be; raise the CPU limit or reduce load"
                elif [ "$CPU_OF_LIMIT_PCT" != "n/a" ] && [ "$CPU_OF_LIMIT_PCT" -ge "$POD_CPU_WARN_PCT" ] 2>/dev/null; then
                    warn "Pod $NS/$POD CPU usage is ${CPU_OF_LIMIT_PCT}% of its limit (${USAGE_CPU_M}m/${LIM_CPU_M}m)."
                fi

                if [ "$MEM_OF_LIMIT_PCT" != "n/a" ] && [ "$MEM_OF_LIMIT_PCT" -ge "$POD_MEM_CRIT_PCT" ] 2>/dev/null; then
                    error "Pod $NS/$POD memory usage is ${MEM_OF_LIMIT_PCT}% of its limit (${USAGE_MEM_MI}Mi/${LIM_MEM_MI}Mi) -- at high risk of imminent OOMKill."
                    record_fact 46 POD_MEM_HIGH "$NS" "$POD" "developer-or-infra" "Memory usage ${MEM_OF_LIMIT_PCT}% of limit (${USAGE_MEM_MI}Mi/${LIM_MEM_MI}Mi) -- likely to be OOMKilled soon; raise the memory limit or investigate a possible leak"
                elif [ "$MEM_OF_LIMIT_PCT" != "n/a" ] && [ "$MEM_OF_LIMIT_PCT" -ge "$POD_MEM_WARN_PCT" ] 2>/dev/null; then
                    warn "Pod $NS/$POD memory usage is ${MEM_OF_LIMIT_PCT}% of its limit (${USAGE_MEM_MI}Mi/${LIM_MEM_MI}Mi)."
                fi
            fi
        fi

        # CONFIRMED_REDIS requires strong evidence (image contains redis/valkey,
        # a container literally named "redis", or the standard Redis ports).
        # POSSIBLE_CACHE is name-only ("cache", "session-store", etc.) and is
        # reported separately -- it is NOT treated as Redis for health rollup,
        # since memcached/hazelcast/valkey/app caches would otherwise get
        # mislabeled as Redis.
        CONFIRMED_REDIS=0
        POSSIBLE_CACHE=0
        echo "$POD" | grep -Eqi '(^|-)redis(-|$)' && CONFIRMED_REDIS=1
        echo "$POD" | grep -Eqi '(^|-)cache(-|$)|session-store|(^|-)data-store(-|$)' && POSSIBLE_CACHE=1

        CONTAINERS=$(kubectl get pod "$POD" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{"\n"}{end}' 2>/dev/null)

        for CONTAINER in $CONTAINERS; do
            echo "$CONTAINER" | grep -Eqi '(^|-)redis(-|$)' && CONFIRMED_REDIS=1
            echo "$CONTAINER" | grep -Eqi '(^|-)cache(-|$)|session-store' && POSSIBLE_CACHE=1
            IMAGE=$(kubectl get pod "$POD" -n "$NS" -o jsonpath="{.spec.containers[?(@.name=='$CONTAINER')].image}" 2>/dev/null)
            echo "$IMAGE" | grep -Eqi 'redis|valkey' && CONFIRMED_REDIS=1
            PORTS=$(kubectl get pod "$POD" -n "$NS" -o jsonpath="{.spec.containers[?(@.name=='$CONTAINER')].ports[*].containerPort}" 2>/dev/null)
            echo "$PORTS" | grep -Eq '(^|[^[:alnum:]_])(6379|6380)([^[:alnum:]_]|$)' && CONFIRMED_REDIS=1

            STATE=$(kubectl get pod "$POD" -n "$NS" -o jsonpath="{.status.containerStatuses[?(@.name=='$CONTAINER')].state}" 2>/dev/null)
            LAST_STATE=$(kubectl get pod "$POD" -n "$NS" -o jsonpath="{.status.containerStatuses[?(@.name=='$CONTAINER')].lastState}" 2>/dev/null)
            RESTARTS=$(kubectl get pod "$POD" -n "$NS" -o jsonpath="{.status.containerStatuses[?(@.name=='$CONTAINER')].restartCount}" 2>/dev/null)
            EXIT_CODE=$(kubectl get pod "$POD" -n "$NS" -o jsonpath="{.status.containerStatuses[?(@.name=='$CONTAINER')].lastState.terminated.exitCode}" 2>/dev/null)
            REASON=$(kubectl get pod "$POD" -n "$NS" -o jsonpath="{.status.containerStatuses[?(@.name=='$CONTAINER')].lastState.terminated.reason}" 2>/dev/null)
            FINISHED=$(kubectl get pod "$POD" -n "$NS" -o jsonpath="{.status.containerStatuses[?(@.name=='$CONTAINER')].lastState.terminated.finishedAt}" 2>/dev/null)

            echo "CONTAINER $CONTAINER  restarts=$RESTARTS  state=$STATE  lastState=$LAST_STATE  exitCode=$EXIT_CODE reason=$REASON finishedAt=$FINISHED" >> "$REPORT"

            if [ -n "$RESTARTS" ] && [ "$RESTARTS" -gt 0 ] 2>/dev/null; then
                warn "Container $NS/$POD/$CONTAINER restarted $RESTARTS time(s). Last reason=$REASON exitCode=$EXIT_CODE finishedAt=$FINISHED"
                fix "kubectl logs $POD -n $NS -c $CONTAINER --previous --timestamps"
                record_fact 50 RESTART "$NS" "$POD/$CONTAINER" "developer" "$RESTARTS restart(s), lastReason=$REASON exitCode=$EXIT_CODE finishedAt=$FINISHED"
            fi

            if echo "$LAST_STATE" | grep -qi "OOMKilled"; then
                critical "Container $NS/$POD/$CONTAINER was OOMKilled (exitCode=$EXIT_CODE, finishedAt=$FINISHED)."
                fix "kubectl top pod $POD -n $NS"
                fix "kubectl get pod $POD -n $NS -o yaml   # review resources.limits"
                record_fact 45 OOM "$NS" "$POD/$CONTAINER" "developer-or-infra" "OOMKilled at $FINISHED (exitCode=$EXIT_CODE) -- either app memory leak/spike or limits set too low"
            fi

            if [ "$ENABLE_LOG_SCAN" = "1" ]; then
                LOG_FILE="$REPORT_DIR/logs/${NS}_${POD}_${CONTAINER}.log"
                kubectl logs "$POD" -n "$NS" -c "$CONTAINER" \
                    --since="${SCAN_MINUTES}m" --timestamps > "$LOG_FILE" 2>&1

                PREV_LOG_FILE="$REPORT_DIR/logs/${NS}_${POD}_${CONTAINER}_previous.log"
                kubectl logs "$POD" -n "$NS" -c "$CONTAINER" \
                    --previous --timestamps > "$PREV_LOG_FILE" 2>&1

                ERROR_PATTERN='error|exception|caused by|traceback|stack trace|fatal|panic|critical|failed|failure|timeout|timed out|connection refused|connection reset|broken pipe|(^|[^[:alnum:]_])oom([^[:alnum:]_]|$)|outofmemory|segmentation fault|permission denied|(^|[^[:alnum:]_])50[234]([^[:alnum:]_]|$)|servfail|nxdomain|certificate'
                if [ -n "$NOISE_EXCLUDE_PATTERN" ]; then
                    MATCHES_TXT=$(grep -Ei "$ERROR_PATTERN" "$LOG_FILE" 2>/dev/null | grep -Ev "$NOISE_EXCLUDE_PATTERN" 2>/dev/null)
                else
                    MATCHES_TXT=$(grep -Ei "$ERROR_PATTERN" "$LOG_FILE" 2>/dev/null)
                fi

                if [ -n "$MATCHES_TXT" ]; then
                    error "Errors found in $NS/$POD/$CONTAINER logs (last ${SCAN_MINUTES}m)."
                    # Structured, multi-line-aware extraction: keeps each
                    # exception/stack-trace together as one "Incident"
                    # block instead of a flat grep dump that can sever a
                    # trace from the line that triggered it.
                    INCIDENT_BLOCKS_RAW=$(extract_incident_blocks "$LOG_FILE" "$ERROR_PATTERN")
                    if [ -n "$INCIDENT_BLOCKS_RAW" ]; then
                        format_incident_blocks "$INCIDENT_BLOCKS_RAW" "$NS/$POD/$CONTAINER" | redact >> "$ERROR_REPORT"
                    else
                        { echo ""; echo "POD: $NS/$POD  CONTAINER: $CONTAINER"; echo "$MATCHES_TXT" | redact; } >> "$ERROR_REPORT"
                    fi
                    fix "kubectl logs $POD -n $NS -c $CONTAINER --since=${SCAN_MINUTES}m --timestamps"
                    FIRST_ERR_LINE=$(echo "$MATCHES_TXT" | head -1 | cut -c1-200 | redact)
                    LOG_TS=$(extract_log_ts "$FIRST_ERR_LINE")
                    record_fact 60 LOG_ERROR "$NS" "$POD/$CONTAINER" "developer" "$FIRST_ERR_LINE" "$LOG_TS"
                fi

                # --- Security-relevant patterns (auth, TLS/certs, RBAC) ---
                SECURITY_MATCHES=$(grep -Ei \
                    'unauthorized|forbidden|permission denied|(^|[^[:alnum:]_])40[13]([^[:alnum:]_]|$)|x509|certificate.*(expired|invalid|unknown authority)|tls handshake|ssl.*(error|fail)|no route to host.*(blocked|denied)|access denied|authentication fail|token.*(expired|invalid)' \
                    "$LOG_FILE" 2>/dev/null)
                if [ -n "$NOISE_EXCLUDE_PATTERN" ] && [ -n "$SECURITY_MATCHES" ]; then
                    SECURITY_MATCHES=$(echo "$SECURITY_MATCHES" | grep -Ev "$NOISE_EXCLUDE_PATTERN" 2>/dev/null)
                fi
                if [ -n "$SECURITY_MATCHES" ]; then
                    error "Security-relevant errors found in $NS/$POD/$CONTAINER logs (last ${SCAN_MINUTES}m)."
                    { echo ""; echo "SECURITY: $NS/$POD/$CONTAINER"; echo "$SECURITY_MATCHES" | redact; } >> "$ERROR_REPORT"
                    FIRST_SEC_LINE=$(echo "$SECURITY_MATCHES" | head -1 | cut -c1-200 | redact)
                    SEC_TS=$(extract_log_ts "$FIRST_SEC_LINE")
                    record_fact 38 SECURITY "$NS" "$POD/$CONTAINER" "security" "$FIRST_SEC_LINE" "$SEC_TS"
                    fix "kubectl describe pod $POD -n $NS   # check ServiceAccount / RBAC / mounted secrets"
                    fix "kubectl logs $POD -n $NS -c $CONTAINER --since=${SCAN_MINUTES}m --timestamps"
                fi

                search_context "$LOG_FILE" "current logs: $NS/$POD/$CONTAINER"
                search_context "$PREV_LOG_FILE" "previous logs: $NS/$POD/$CONTAINER"

                if [ $CONFIRMED_REDIS -eq 1 ]; then
                    REDIS_FOUND=1
                    REDIS_MATCHES=$(grep -Ei \
                        'oom|out of memory|misconf|readonly|loading|noauth|connection refused|connection reset|timeout|timed out|broken pipe|maxmemory|evicted|master|replica|sentinel|cluster.*fail|error|exception' \
                        "$LOG_FILE" 2>/dev/null)
                    if [ -n "$REDIS_MATCHES" ]; then
                        error "Redis-related issues found in $NS/$POD/$CONTAINER."
                        { echo ""; echo "REDIS: $NS/$POD/$CONTAINER"; echo "$REDIS_MATCHES" | redact; } >> "$ERROR_REPORT"
                        FIRST_REDIS_LINE=$(echo "$REDIS_MATCHES" | head -1 | cut -c1-200 | redact)
                        REDIS_TS=$(extract_log_ts "$FIRST_REDIS_LINE")
                        record_fact 35 REDIS_ERROR "$NS" "$POD/$CONTAINER" "infra-or-developer" "$FIRST_REDIS_LINE" "$REDIS_TS"
                        set_redis_status 3 "DETECTED / INVESTIGATION REQUIRED"
                    fi
                    if [ -n "$RESTARTS" ] && [ "$RESTARTS" -gt 0 ] 2>/dev/null; then
                        set_redis_status 3 "DETECTED / INVESTIGATION REQUIRED"
                    fi
                    if echo "$LAST_STATE" | grep -qi "OOMKilled"; then
                        set_redis_status 4 "DETECTED / NO READY ENDPOINTS (last OOMKilled)"
                    fi
                    if [ "$READY_COND" = "False" ]; then
                        set_redis_status 4 "DETECTED / NOT READY"
                    fi
                    if [ -z "$REDIS_MATCHES" ] && [ "$READY_COND" != "False" ] && { [ -z "$RESTARTS" ] || [ "$RESTARTS" -eq 0 ] 2>/dev/null; }; then
                        set_redis_status 2 "DETECTED / HEALTH EVIDENCE GOOD"
                    fi
                elif [ $POSSIBLE_CACHE -eq 1 ]; then
                    set_redis_status 1 "DETECTED / UNVERIFIED (name-only cache match, not confirmed Redis -- could be memcached/valkey/app cache)"
                fi
            fi
        done

        # Optional read-only network probe (off by default)
        if [ "$ENABLE_POD_NETWORK_TEST" = "1" ] && [ -n "$CONTAINERS" ]; then
            FIRST_CONTAINER=$(echo "$CONTAINERS" | head -1)
            echo "POD NETWORK INFO ($NS/$POD):" >> "$REPORT"
            kubectl exec "$POD" -n "$NS" -c "$FIRST_CONTAINER" -- \
                sh -c 'hostname; cat /etc/resolv.conf; echo "--- ROUTES ---"; (ip route || route -n) 2>/dev/null' \
                >> "$REPORT" 2>&1
        fi
    done
done

if [ $REDIS_FOUND -eq 1 ]; then
    set_redis_status 2 "DETECTED / HEALTH EVIDENCE GOOD"
fi

###############################################################################
# 5. COREDNS DETAIL
###############################################################################

section "5. CORE DNS"

kubectl get pods -n kube-system -l k8s-app=kube-dns -o wide >> "$REPORT" 2>&1
kubectl get svc kube-dns -n kube-system -o wide >> "$REPORT" 2>&1

DNS_PODS=$(kubectl get pods -n kube-system -l k8s-app=kube-dns -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null)
for DNS_POD in $DNS_PODS; do
    LOG_FILE="$REPORT_DIR/logs/coredns_${DNS_POD}.log"
    kubectl logs "$DNS_POD" -n kube-system --since="${SCAN_MINUTES}m" > "$LOG_FILE" 2>&1
    DNS_MATCHES=$(grep -Ei 'error|fatal|panic|timeout|plugin/errors|servfail|refused' "$LOG_FILE" 2>/dev/null)
    if [ -n "$DNS_MATCHES" ]; then
        echo "$DNS_MATCHES" >> "$ERROR_REPORT"
        FIRST_DNS_LINE=$(echo "$DNS_MATCHES" | head -1 | cut -c1-200 | redact)
        record_fact 30 DNS_ERROR kube-system "$DNS_POD" "infra" "$FIRST_DNS_LINE" "$(extract_log_ts "$FIRST_DNS_LINE")"
    fi
    search_context "$LOG_FILE" "coredns: $DNS_POD"
done

###############################################################################
# 6. INGRESS / HAPROXY
###############################################################################

section "6. INGRESS / HAPROXY / PROXY"

# Detect by pod name (broadened beyond just "haproxy|ingress") AND by
# container image, since real deployments are often named "gateway",
# "edge", "lb", "router", or use nginx/traefik/envoy under a custom name.
HA_PODS_BY_NAME=$(kubectl get pods -A -o custom-columns='NS:.metadata.namespace,NAME:.metadata.name' --no-headers 2>/dev/null \
    | grep -Ei 'haproxy|ingress|nginx|traefik|envoy|gateway|controller|edge-proxy|(^|[^[:alnum:]_])lb([^[:alnum:]_]|$)|router' || true)

HA_PODS_BY_IMAGE=$(kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{" "}{.metadata.name}{" "}{range .spec.containers[*]}{.image}{","}{end}{"\n"}{end}' 2>/dev/null \
    | grep -Ei 'haproxy|nginx|traefik|envoyproxy|/envoy|ingress-nginx' \
    | awk '{print $1" "$2}' || true)

HA_PODS=$(printf '%s\n%s\n' "$HA_PODS_BY_NAME" "$HA_PODS_BY_IMAGE" | awk 'NF' | sort -u)

if [ -n "$HA_PODS" ]; then
    while read -r NS POD; do
        [ -z "$POD" ] && continue
        LOG_FILE="$REPORT_DIR/logs/${NS}_${POD}_ingress.log"
        kubectl logs "$POD" -n "$NS" --all-containers --since="${SCAN_MINUTES}m" --timestamps > "$LOG_FILE" 2>&1
        HAPROXY_MATCHES=$(grep -Ei '(^|[^[:alnum:]_])50[234]([^[:alnum:]_]|$)|timeout|connection refused|connection reset|no server|backend.*down|server.*down' "$LOG_FILE" 2>/dev/null)
        if [ -n "$HAPROXY_MATCHES" ]; then
            error "Proxy/Ingress errors in $NS/$POD (last ${SCAN_MINUTES}m)."
            { echo ""; echo "INGRESS: $NS/$POD"; echo "$HAPROXY_MATCHES" | redact; } >> "$ERROR_REPORT"
            FIRST_HA_LINE=$(echo "$HAPROXY_MATCHES" | head -1 | cut -c1-200 | redact)
            record_fact 70 HAPROXY_5XX "$NS" "$POD" "downstream-symptom" "$FIRST_HA_LINE" "$(extract_log_ts "$FIRST_HA_LINE")"
        fi
        search_context "$LOG_FILE" "ingress/proxy: $NS/$POD"
    done <<< "$HA_PODS"
else
    info "No Kubernetes-hosted ingress/proxy workload was detected by the available pod/image metadata. This does NOT rule out an external load balancer (cloud ALB, F5, Cloudflare, hardware LB) with no corresponding pod."
fi

###############################################################################
# 6B. F5 / EXTERNAL LOAD BALANCER (PLUGGABLE HOOK, OFF UNLESS CONFIGURED)
#
# This scanner only talks to the Kubernetes API -- it has no visibility
# into an external appliance like an F5 BIG-IP sitting in front of the
# cluster, and it makes no network calls to one. Instead this is a
# pluggable hook: point it at logs you already export, or at your own
# read-only export command, and matches are folded into the same
# correlation engine, error catalog, and HTML report as everything else.
# If neither F5_LOG_SOURCE nor F5_LOG_HOOK is set, this is skipped and
# clearly marked "not configured" rather than silently omitted.
###############################################################################

section "6B. F5 / EXTERNAL LOAD BALANCER"

F5_MATCHES_COUNT=0

if [ -z "$F5_LOG_SOURCE" ] && [ -z "$F5_LOG_HOOK" ]; then
    info "F5/external LB scanning not configured (set F5_LOG_SOURCE and/or F5_LOG_HOOK). This scanner has no direct visibility into appliance-based load balancers/WAFs -- see Coverage Limitations in the HTML report."
else
    if [ -n "$F5_LOG_HOOK" ]; then
        if [ -x "$F5_LOG_HOOK" ]; then
            info "Running F5 log hook: $F5_LOG_HOOK (must be read-only by design of the hook itself; this scanner only consumes its stdout and does not verify that)."
            if command_exists timeout; then
                timeout 30 "$F5_LOG_HOOK" >> "$F5_REPORT" 2>"$REPORT_DIR/data/f5-hook-stderr.log"
            else
                "$F5_LOG_HOOK" >> "$F5_REPORT" 2>"$REPORT_DIR/data/f5-hook-stderr.log"
            fi
        else
            warn "F5_LOG_HOOK is set to '$F5_LOG_HOOK' but is not an executable file. Skipping."
        fi
    fi

    if [ -n "$F5_LOG_SOURCE" ]; then
        if [ -f "$F5_LOG_SOURCE" ]; then
            cat "$F5_LOG_SOURCE" >> "$F5_REPORT" 2>/dev/null
        elif [ -d "$F5_LOG_SOURCE" ]; then
            find "$F5_LOG_SOURCE" -type f 2>/dev/null | while read -r f; do cat "$f" 2>/dev/null; done >> "$F5_REPORT"
        else
            warn "F5_LOG_SOURCE '$F5_LOG_SOURCE' is not a readable file or directory. Skipping."
        fi
    fi

    if [ -s "$F5_REPORT" ]; then
        F5_MATCHES_TXT=$(grep -Ei "$F5_BLOCK_PATTERN" "$F5_REPORT" 2>/dev/null)
        if [ -n "$F5_MATCHES_TXT" ]; then
            F5_MATCHES_COUNT=$(echo "$F5_MATCHES_TXT" | grep -c .)
            error "F5/external LB blocking or failure patterns found ($F5_MATCHES_COUNT line(s)) in the supplied F5 log source."
            { echo ""; echo "F5 / EXTERNAL LB (full matched lines):"; echo "$F5_MATCHES_TXT" | redact; } >> "$ERROR_REPORT"
            FIRST_F5_LINE=$(echo "$F5_MATCHES_TXT" | head -1 | cut -c1-200 | redact)
            F5_TS=$(extract_log_ts "$FIRST_F5_LINE")
            record_fact 38 F5_BLOCKED "-" "external-f5" "network" "$FIRST_F5_LINE ($F5_MATCHES_COUNT total matching line(s) in supplied F5 log source)" "$F5_TS"
            fix "Review full F5 match context in: $F5_REPORT"
            fix "On the BIG-IP: search the ASM event log using the support_id shown in the matched line"
            fix "On the BIG-IP: tmsh show ltm pool <pool> members   # check monitor status"
            fix "On the BIG-IP: tmsh show ltm virtual <vs> profiles"
            fix "On the BIG-IP: review any iRule on the affected virtual server for a drop/reject action"
        else
            info "F5 log source ingested ($(wc -l < "$F5_REPORT" 2>/dev/null | tr -d ' ') line(s)) -- no blocking/failure patterns matched F5_BLOCK_PATTERN."
        fi
        search_context "$F5_REPORT" "F5/external LB log"
    else
        warn "F5_LOG_SOURCE/F5_LOG_HOOK was configured but produced no data to scan."
    fi
fi

###############################################################################
# 7. RESOURCE USAGE / STORAGE
###############################################################################

section "7. RESOURCE USAGE AND STORAGE"

if [ "$POD_METRICS_AVAILABLE" = "1" ]; then
    # Not sorted here with `sort -h`: GNU sort's human-numeric sort does
    # not understand Kubernetes' millicore "m" suffix (e.g. "450m") and
    # would silently mis-order the CPU column. The properly unit-converted,
    # correctly sortable comparison lives in the "Pod Resource Usage"
    # section of the HTML report instead, built from the same snapshot
    # using this script's own cpu_to_millicores/mem_to_mi conversion.
    cat "$POD_METRICS_FILE" >> "$REPORT"
    info "Per-pod CPU/memory usage: see the 'Pod Resource Usage' section of the HTML report for usage cross-referenced against each pod's own requests/limits."
else
    warn "Metrics Server data unavailable."
fi

kubectl get pvc -A -o wide >> "$REPORT" 2>&1
PVC_PROBLEMS=$(kubectl get pvc -A --no-headers 2>/dev/null | awk '$3!="Bound"')
if [ -n "$PVC_PROBLEMS" ]; then
    PVC_COUNT=$(echo "$PVC_PROBLEMS" | grep -c .)
    warn "$PVC_COUNT PVC(s) not in Bound state:"
    { echo ""; echo "PVCs NOT BOUND ($PVC_COUNT):"; } >> "$ERROR_REPORT"
    while read -r pvc_ns pvc_name pvc_status pvc_rest; do
        [ -z "$pvc_name" ] && continue
        PVC_SCOPE_NOTE=""
        if [ -n "$SELECTED_NS" ] && [ "$pvc_ns" != "$SELECTED_NS" ]; then
            PVC_SCOPE_NOTE="  (outside selected scope: $SELECTED_NS)"
        fi
        echo "    $pvc_ns/$pvc_name  status=$pvc_status$PVC_SCOPE_NOTE"
        echo "  $pvc_ns/$pvc_name  status=$pvc_status$PVC_SCOPE_NOTE" >> "$ERROR_REPORT"
        fix "kubectl describe pvc $pvc_name -n $pvc_ns"
        if [ -z "$PVC_SCOPE_NOTE" ]; then
            record_fact 55 PVC_NOT_BOUND "$pvc_ns" "$pvc_name" "infra" "PVC $pvc_name is $pvc_status (not Bound) -- check the StorageClass/provisioner and PV availability"
        fi
    done <<< "$PVC_PROBLEMS"
fi

###############################################################################
# 8. ROOT CAUSE CORRELATION ENGINE
#
# Groups every recorded fact by namespace (facts with namespace "-" are
# cluster/node-wide and apply to everything downstream). Within a group,
# the LOWEST rank (most "upstream" category) is presented as the root
# cause CANDIDATE; everything else in that group is shown as related
# evidence/symptoms. This is evidence-based correlation, not proof --
# the report always says "candidate", and always lists raw evidence.
###############################################################################

section "8. ROOT CAUSE ANALYSIS"

ROOTCAUSE_HTML="$REPORT_DIR/data/rootcause.html.frag"
: > "$ROOTCAUSE_HTML"

owner_label() {
    case "$1" in
        infra) echo "Infra / Platform team" ;;
        network) echo "Network team" ;;
        developer) echo "Application developer" ;;
        security) echo "Security team" ;;
        infra-or-developer) echo "Infra (limits) or Developer (memory usage) -- needs joint review" ;;
        developer-or-network) echo "Developer (readiness probe / selector) or Network team (policy) -- needs joint review" ;;
        developer-or-infra) echo "Infra or Developer" ;;
        developer-or-security) echo "Developer (auth/token handling) or Security team (cert/RBAC) -- needs joint review" ;;
        infra-or-network) echo "Infra or Network" ;;
        downstream-symptom) echo "N/A -- symptom of an upstream issue, not the root cause itself" ;;
        *) echo "Needs investigation" ;;
    esac
}

suggest_cmds() {
    # $1 category  $2 namespace  $3 resource
    local cat="$1" ns="$2" res="$3"
    case "$cat" in
        CONTROL_PLANE) echo "kubectl get --raw='/readyz?verbose'|kubectl get --raw='/livez?verbose'" ;;
        NODE_NOT_READY|NODE_PRESSURE) echo "kubectl describe node $res|kubectl top node $res|kubectl get pods -A -o wide --field-selector spec.nodeName=$res" ;;
        NODE_NETWORK) echo "kubectl describe node $res" ;;
        DNS_ERROR) echo "kubectl logs $res -n kube-system --since=${SCAN_MINUTES}m|kubectl get svc kube-dns -n kube-system" ;;
        SECURITY) echo "kubectl describe pod ${res%%/*} -n $ns   # ServiceAccount/RBAC/mounted secrets|kubectl auth can-i --list --as=system:serviceaccount:$ns:default -n $ns|kubectl get rolebinding,clusterrolebinding -n $ns|kubectl logs ${res%%/*} -n $ns -c ${res##*/} --since=${SCAN_MINUTES}m" ;;
        REDIS_ERROR) echo "kubectl describe pod ${res%%/*} -n $ns|kubectl logs ${res%%/*} -n $ns -c ${res##*/} --since=${SCAN_MINUTES}m|kubectl top pod ${res%%/*} -n $ns" ;;
        NO_ENDPOINTS) echo "kubectl describe svc $res -n $ns|kubectl get endpointslices -n $ns -l kubernetes.io/service-name=$res -o wide|kubectl get pods -n $ns --show-labels" ;;
        READINESS_FAIL) echo "kubectl describe pod ${res%%/*} -n $ns|kubectl logs ${res%%/*} -n $ns --since=${SCAN_MINUTES}m" ;;
        OOM) echo "kubectl top pod ${res%%/*} -n $ns|kubectl get pod ${res%%/*} -n $ns -o yaml   # check resources.limits.memory" ;;
        RESTART) echo "kubectl logs ${res%%/*} -n $ns -c ${res##*/} --previous --timestamps|kubectl describe pod ${res%%/*} -n $ns" ;;
        PENDING_SCHEDULING) echo "kubectl describe pod $res -n $ns|kubectl top nodes|kubectl get resourcequota -n $ns|kubectl get pvc -n $ns" ;;
        PENDING_CONTAINER_ERROR) echo "kubectl describe pod $res -n $ns   # check Events for the exact image/config/secret error|kubectl get pod $res -n $ns -o jsonpath='{.status.containerStatuses[*].state.waiting.message}'" ;;
        FAILED|UNKNOWN) echo "kubectl describe pod $res -n $ns|kubectl logs $res -n $ns --all-containers" ;;
        STATEFULSET_NOT_READY) echo "kubectl describe statefulset $res -n $ns|kubectl get pods -n $ns -l app=$res" ;;
        JOB_FAILED) echo "kubectl describe job $res -n $ns|kubectl logs -n $ns -l job-name=$res --all-containers --tail=200" ;;
        CRONJOB_UNCERTAIN) echo "kubectl describe cronjob $res -n $ns|kubectl get jobs -n $ns | grep $res" ;;
        LOG_ERROR) echo "kubectl logs ${res%%/*} -n $ns -c ${res##*/} --since=${SCAN_MINUTES}m --timestamps" ;;
        HAPROXY_5XX) echo "kubectl logs $res -n $ns --since=${SCAN_MINUTES}m|kubectl get endpoints -n $ns   # find the backend returning 5xx" ;;
        PROBE_FAIL) echo "kubectl exec ${res%%/*} -n $ns -c ${res##*/} -- curl -v -m ${PROBE_TIMEOUT} http://127.0.0.1:<port>${PROBE_PATH}|kubectl describe pod ${res%%/*} -n $ns|kubectl logs ${res%%/*} -n $ns -c ${res##*/} --since=${SCAN_MINUTES}m" ;;
        F5_BLOCKED) echo "Review full match context in the report's data/f5-external.log|On BIG-IP: search the ASM event log using the support_id in the matched line|On BIG-IP: tmsh show ltm pool <pool> members|On BIG-IP: tmsh show ltm virtual <vs> profiles|On BIG-IP: review iRules on the affected virtual server for drop/reject actions" ;;
        API_LATENCY) echo "kubectl get --raw='/readyz?verbose'|kubectl get --raw='/livez?verbose'|kubectl get componentstatuses 2>/dev/null|kubectl logs -n kube-system -l component=etcd --since=${SCAN_MINUTES}m --timestamps" ;;
        ETCD_SLOW) echo "kubectl logs $res -n kube-system --since=${SCAN_MINUTES}m --timestamps | grep -Ei 'slow fdatasync|took too long'|On the node hosting $res: check disk I/O latency (iostat/fio) -- etcd fsyncs on every write" ;;
        NODE_OVERSUBSCRIBED) echo "kubectl describe node $res   # see 'Allocated resources' section|kubectl get pods -A --field-selector spec.nodeName=$res -o wide|kubectl top pod -A --field-selector spec.nodeName=$res 2>/dev/null" ;;
        HPA_INACTIVE) echo "kubectl describe hpa $res -n $ns   # check Conditions for the exact reason|kubectl get pods -n kube-system -l k8s-app=metrics-server|kubectl top pods -n $ns" ;;
        HPA_MAXED) echo "kubectl describe hpa $res -n $ns|kubectl top pods -n $ns|kubectl describe node   # check if there is spare node capacity for more replicas" ;;
        POD_CPU_HIGH) echo "kubectl top pod $res -n $ns --containers|kubectl get pod $res -n $ns -o jsonpath='{.spec.containers[*].resources}'|kubectl describe pod $res -n $ns   # review resources.limits.cpu" ;;
        POD_MEM_HIGH) echo "kubectl top pod $res -n $ns --containers|kubectl get pod $res -n $ns -o jsonpath='{.spec.containers[*].resources}'|kubectl describe pod $res -n $ns   # review resources.limits.memory" ;;
        PVC_NOT_BOUND) echo "kubectl describe pvc $res -n $ns|kubectl get storageclass|kubectl get pv" ;;
        *) echo "kubectl describe pod $res -n $ns" ;;
    esac
}

html_escape() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }

###############################################################################
# WORKLOAD RESOLUTION -- fixes namespace-level over-grouping in root-cause
# correlation. Previously, every fact in a namespace was bucketed together
# regardless of which actual Deployment/StatefulSet/Job it belonged to, so
# a namespace with several unrelated simultaneous incidents would show one
# as the "root cause" and nest the others underneath it as if related, even
# with no causal link. This resolves each pod-level fact to its real owning
# workload (via ownerReferences: Pod -> ReplicaSet -> Deployment, or Pod ->
# StatefulSet/Job/DaemonSet directly) and each service-level fact to the
# workload behind one of its actual endpoint pods -- so unrelated incidents
# in the same namespace are correctly kept in separate candidates. A
# Service with ZERO endpoints has no pod to resolve from, so it correctly
# stays its own isolated group rather than being merged into anything --
# that absence of endpoints IS the finding.
#
# Read-only: only `kubectl get` calls, cached per pod so repeat facts about
# the same pod don't re-query the API.
###############################################################################
declare -A WORKLOAD_CACHE
resolve_workload() {
    # $1 ns  $2 pod  -> prints the owning workload name (Deployment/
    # StatefulSet/Job/DaemonSet), or the pod's own name if unresolvable.
    local ns="$1" pod="$2" cache_key="${1}/${2}"
    if [ -n "${WORKLOAD_CACHE[$cache_key]+set}" ]; then
        echo "${WORKLOAD_CACHE[$cache_key]}"
        return
    fi
    local kind name result
    kind=$(kubectl get pod "$pod" -n "$ns" -o jsonpath='{.metadata.ownerReferences[0].kind}' 2>/dev/null)
    name=$(kubectl get pod "$pod" -n "$ns" -o jsonpath='{.metadata.ownerReferences[0].name}' 2>/dev/null)
    if [ "$kind" = "ReplicaSet" ] && [ -n "$name" ]; then
        local deploy
        deploy=$(kubectl get replicaset "$name" -n "$ns" -o jsonpath='{.metadata.ownerReferences[0].name}' 2>/dev/null)
        result="${deploy:-$name}"
    elif [ -n "$name" ]; then
        result="$name"
    else
        result="$pod"
    fi
    WORKLOAD_CACHE[$cache_key]="$result"
    echo "$result"
}

resolve_service_workload() {
    # $1 ns  $2 svc  -> resolves via one of the service's own endpoint pods
    # (already recorded in service-topology.tsv), so no extra selector
    # matching is needed. Falls back to an isolated "svc:<name>" group key
    # when the service has no endpoint pod to resolve from at all.
    local ns="$1" svc="$2" row podlist first_pod
    row=$(awk -F'\t' -v ns="$ns" -v svc="$svc" '$1==ns && $2==svc' "$REPORT_DIR/data/service-topology.tsv" 2>/dev/null | head -1)
    if [ -z "$row" ]; then
        echo "svc:$svc"
        return
    fi
    podlist=$(echo "$row" | awk -F'\t' '{print $4" "$5}')
    first_pod=$(echo "$podlist" | grep -oE '\([^)]+\)' | head -1 | tr -d '()')
    if [ -n "$first_pod" ]; then
        resolve_workload "$ns" "$first_pod"
    else
        echo "svc:$svc"
    fi
}

ROOT_CAUSE_COUNT=0

# --- Cluster/node-wide facts (namespace field is "-") ---
CLUSTER_FACTS=$(awk -F'\t' '$3=="-"' "$FACTS_FILE" | sort -t$'\t' -k1,1n)
if [ -n "$CLUSTER_FACTS" ]; then
    TOP=$(echo "$CLUSTER_FACTS" | head -1)
    RANK=$(echo "$TOP" | cut -f1); CAT=$(echo "$TOP" | cut -f2); RES=$(echo "$TOP" | cut -f4); OWNER=$(echo "$TOP" | cut -f5); DETAIL=$(echo "$TOP" | cut -f6)
    ROOT_CAUSE_COUNT=$((ROOT_CAUSE_COUNT+1))
    {
        echo "============================================================"
        echo "ROOT-CAUSE CANDIDATE / INVESTIGATION LEAD #$ROOT_CAUSE_COUNT  (cluster-wide)"
        echo "============================================================"
        echo "Category : $CAT"
        echo "Resource : $RES"
        echo "Owner    : $(owner_label "$OWNER")"
        echo "Evidence : $DETAIL"
        echo ""
        echo "This affects every namespace/pod scheduled on/behind it, so it is"
        echo "listed ahead of namespace-level findings."
        echo ""
        echo "Suggested investigation commands:"
        suggest_cmds "$CAT" "-" "$RES" | tr '|' '\n' | sed 's/^/  /'
        echo ""
    } >> "$ROOTCAUSE_REPORT"

    {
        echo "<div class=\"card\"><h3>Root-Cause Candidate / Investigation Lead #$ROOT_CAUSE_COUNT <span class=\"badge crit\">cluster-wide</span></h3>"
        echo "<p><b>Category:</b> $(echo "$CAT" | html_escape)<br><b>Resource:</b> $(echo "$RES" | html_escape)<br><b>Likely owner:</b> $(owner_label "$OWNER" | html_escape)</p>"
        echo "<p><b>Evidence:</b> $(echo "$DETAIL" | html_escape)</p>"
        echo "<p><b>Suggested commands (read-only):</b></p><pre>$(suggest_cmds "$CAT" "-" "$RES" | tr '|' '\n' | html_escape)</pre></div>"
    } >> "$ROOTCAUSE_HTML"
fi

# --- Per-namespace facts, grouped by resolved owning workload ---
GROUPED_FACTS="$REPORT_DIR/data/grouped_facts.tsv"
: > "$GROUPED_FACTS"

awk -F'\t' '$3!="-"' "$FACTS_FILE" | while IFS=$'\t' read -r rank cat ns res owner detail ts; do
    [ -z "$rank" ] && continue
    case "$cat" in
        NO_ENDPOINTS|PARTIAL_NOT_READY)
            GKEY=$(resolve_service_workload "$ns" "$res")
            ;;
        *)
            GKEY=$(resolve_workload "$ns" "${res%%/*}")
            ;;
    esac
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$GKEY" "$rank" "$cat" "$ns" "$res" "$owner" "$detail" "$ts" >> "$GROUPED_FACTS"
done

NS_GROUP_PAIRS=$(awk -F'\t' '{print $4"\t"$1}' "$GROUPED_FACTS" | sort -u -t$'\t' -k1,1 -k2,2)

while IFS=$'\t' read -r NS GKEY; do
    [ -z "$NS" ] && continue
    GROUP_FACTS=$(awk -F'\t' -v ns="$NS" -v gk="$GKEY" '$4==ns && $1==gk' "$GROUPED_FACTS" | sort -t$'\t' -k2,2n)
    ROOT=$(echo "$GROUP_FACTS" | head -1)
    REST=$(echo "$GROUP_FACTS" | tail -n +2)

    RANK=$(echo "$ROOT" | cut -f2); CAT=$(echo "$ROOT" | cut -f3); RES=$(echo "$ROOT" | cut -f5); OWNER=$(echo "$ROOT" | cut -f6); DETAIL=$(echo "$ROOT" | cut -f7)
    ROOT_CAUSE_COUNT=$((ROOT_CAUSE_COUNT+1))

    {
        echo "============================================================"
        echo "ROOT-CAUSE CANDIDATE / INVESTIGATION LEAD #$ROOT_CAUSE_COUNT  (namespace: $NS, workload: $GKEY)"
        echo "============================================================"
        echo "Category : $CAT"
        echo "Resource : $NS/$RES"
        echo "Owner    : $(owner_label "$OWNER")"
        echo "Evidence : $DETAIL"
        echo ""
        if [ -n "$REST" ]; then
            echo "Related evidence for the SAME workload ($GKEY) -- likely part of the same incident:"
            echo "$REST" | while IFS=$'\t' read -r gk2 r c n res2 o d ts2; do
                echo "  - [$c] $n/$res2: $d"
            done
        fi
        echo ""
        echo "Suggested investigation commands:"
        suggest_cmds "$CAT" "$NS" "$RES" | tr '|' '\n' | sed 's/^/  /'
        echo ""
    } >> "$ROOTCAUSE_REPORT"

    {
        echo "<div class=\"card\"><h3>Root-Cause Candidate / Investigation Lead #$ROOT_CAUSE_COUNT <span class=\"badge err\">ns: $(echo "$NS" | html_escape) &middot; workload: $(echo "$GKEY" | html_escape)</span></h3>"
        echo "<p><b>Category:</b> $(echo "$CAT" | html_escape)<br><b>Resource:</b> $(echo "$NS/$RES" | html_escape)<br><b>Likely owner:</b> $(owner_label "$OWNER" | html_escape)</p>"
        echo "<p><b>Evidence:</b> $(echo "$DETAIL" | html_escape)</p>"
        if [ -n "$REST" ]; then
            echo "<p><b>Related evidence for the same workload</b> (likely part of the same incident, not a separate one):</p><pre>"
            echo "$REST" | while IFS=$'\t' read -r gk2 r c n res2 o d ts2; do
                echo "[$c] $n/$res2: $d"
            done | html_escape
            echo "</pre>"
        fi
        echo "<p><b>Suggested commands (read-only):</b></p><pre>$(suggest_cmds "$CAT" "$NS" "$RES" | tr '|' '\n' | html_escape)</pre></div>"
    } >> "$ROOTCAUSE_HTML"
done <<< "$NS_GROUP_PAIRS"

if [ "$ROOT_CAUSE_COUNT" -eq 0 ]; then
    echo "No correlated findings in this scan window -- no root-cause candidates identified." >> "$ROOTCAUSE_REPORT"
    echo "<div class=\"card\">No correlated findings in this scan window.</div>" >> "$ROOTCAUSE_HTML"
fi

echo "Root cause candidates identified: $ROOT_CAUSE_COUNT"

###############################################################################
# 8b. FULL ERROR CATALOG -- every individual detected error/finding, with
# its timestamp, exact pod/container, category, owning team, root-cause
# explanation, and suggested read-only commands. This answers "which pod,
# at what time, what's wrong, who fixes it, with what command" for EVERY
# finding -- not just the top-ranked candidate per namespace.
###############################################################################

CATALOG_REPORT="$REPORT_DIR/error-catalog.txt"
CATALOG_HTML="$REPORT_DIR/data/catalog.html.frag"
: > "$CATALOG_REPORT"
: > "$CATALOG_HTML"

echo "TIMESTAMP           | NAMESPACE/RESOURCE                | CATEGORY        | OWNER TEAM               | DETAIL" >> "$CATALOG_REPORT"
echo "--------------------+------------------------------------+-----------------+---------------------------+------------------------------------------------------------" >> "$CATALOG_REPORT"

{
echo '<table style="width:100%;border-collapse:collapse;font-size:13px">'
echo '<tr style="text-align:left;border-bottom:2px solid #333"><th style="padding:6px">Timestamp</th><th style="padding:6px">Namespace / Pod</th><th style="padding:6px">Category</th><th style="padding:6px">Owner Team</th><th style="padding:6px">Root Cause / Detail</th><th style="padding:6px">Suggested Commands</th></tr>'
} >> "$CATALOG_HTML"

sort -t$'\t' -k7,7 "$FACTS_FILE" | while IFS=$'\t' read -r rank cat ns res owner detail ts; do
    [ -z "$rank" ] && continue
    NSRES="${ns}/${res}"
    [ "$ns" = "-" ] && NSRES="$res (cluster-wide)"
    OWNER_TXT=$(owner_label "$owner")
    CMDS=$(suggest_cmds "$cat" "$ns" "$res" | tr '|' '; ')

    printf '%-20s | %-34s | %-15s | %-25s | %s\n' "$ts" "$NSRES" "$cat" "$OWNER_TXT" "$detail" >> "$CATALOG_REPORT"
    echo "  -> fix: $CMDS" >> "$CATALOG_REPORT"

    SEV_BADGE="err"
    case "$rank" in
        1[0-9]|2[0-9]|3[0-9]) SEV_BADGE="crit" ;;
        4[0-9]|5[0-9]) SEV_BADGE="err" ;;
        *) SEV_BADGE="warn" ;;
    esac

    {
        echo "<tr style=\"border-bottom:1px solid #2a2d36\">"
        echo "<td style=\"padding:6px;white-space:nowrap\">$(echo "$ts" | html_escape)</td>"
        echo "<td style=\"padding:6px\">$(echo "$NSRES" | html_escape)</td>"
        echo "<td style=\"padding:6px\"><span class=\"badge $SEV_BADGE\">$(echo "$cat" | html_escape)</span></td>"
        echo "<td style=\"padding:6px\">$(echo "$OWNER_TXT" | html_escape)</td>"
        echo "<td style=\"padding:6px\">$(echo "$detail" | html_escape)</td>"
        echo "<td style=\"padding:6px\"><pre style=\"margin:0;background:none;border:none;padding:0\">$(echo "$CMDS" | tr ';' '\n' | html_escape)</pre></td>"
        echo "</tr>"
    } >> "$CATALOG_HTML"
done

echo '</table>' >> "$CATALOG_HTML"

CATALOG_COUNT=$(wc -l < "$FACTS_FILE" 2>/dev/null || echo 0)
echo "Total findings in catalog: $CATALOG_COUNT"

###############################################################################
# 8c. SEARCH STATISTICS -- occurrence-aware, not just "N files matched".
###############################################################################

SEARCH_OCCURRENCES=0
SEARCH_RESOURCES=0
SEARCH_NAMESPACES=0
if [ -n "$SEARCH_VALUE" ] && [ -s "$SEARCH_STATS_FILE" ]; then
    SEARCH_OCCURRENCES=$(awk -F'\t' '{s+=$1} END{print s+0}' "$SEARCH_STATS_FILE")
    SEARCH_RESOURCES=$(cut -f2 "$SEARCH_STATS_FILE" | sort -u | wc -l | tr -d ' ')
    # Best-effort namespace extraction: labels look like "current logs: ns/pod/container"
    SEARCH_NAMESPACES=$(cut -f2 "$SEARCH_STATS_FILE" | sed -n 's/^[^:]*: \([^/]*\)\/.*/\1/p' | sort -u | wc -l | tr -d ' ')
fi

###############################################################################
# 9. SUMMARY + HTML REPORT
###############################################################################

section "9. FINAL SUMMARY"

# --- Endpoint probe + F5 summary stats, computed before the HTML build ---
PROBE_TOTAL=0; PROBE_FAIL_COUNT=0; PROBE_OK_COUNT=0
if [ -s "$PROBE_TSV" ]; then
    PROBE_TOTAL=$(wc -l < "$PROBE_TSV" 2>/dev/null | tr -d ' ')
    PROBE_FAIL_COUNT=$(awk -F'\t' '$1=="FAIL"' "$PROBE_TSV" | wc -l | tr -d ' ')
    PROBE_OK_COUNT=$(awk -F'\t' '$1=="OK"' "$PROBE_TSV" | wc -l | tr -d ' ')
fi

if [ "$ENABLE_ENDPOINT_PROBE" != "1" ]; then
    PROBE_STATUS_TEXT="DISABLED"; PROBE_STATUS_CLASS="warn"
elif [ "$PROBE_FAIL_COUNT" -gt 0 ] 2>/dev/null; then
    PROBE_STATUS_TEXT="${PROBE_FAIL_COUNT} FAILED / ${PROBE_TOTAL} probed"; PROBE_STATUS_CLASS="err"
else
    PROBE_STATUS_TEXT="${PROBE_OK_COUNT}/${PROBE_TOTAL} OK"; PROBE_STATUS_CLASS="ok"
fi

if [ -z "$F5_LOG_SOURCE" ] && [ -z "$F5_LOG_HOOK" ]; then
    F5_STATUS_TEXT="NOT CONFIGURED"; F5_STATUS_CLASS="warn"
elif [ "$F5_MATCHES_COUNT" -gt 0 ] 2>/dev/null; then
    F5_STATUS_TEXT="${F5_MATCHES_COUNT} MATCH(ES)"; F5_STATUS_CLASS="err"
else
    F5_STATUS_TEXT="CONFIGURED / CLEAN"; F5_STATUS_CLASS="ok"
fi

# Redis badge color must reflect REDIS_STATUS_RANK, not just whether Redis
# was detected at all -- "NO READY ENDPOINTS" and "INVESTIGATION REQUIRED"
# are real problems and must not render as a green "ok" badge.
case "$REDIS_STATUS_RANK" in
    0) REDIS_STATUS_CLASS="warn" ;;   # NOT DETECTED
    1) REDIS_STATUS_CLASS="warn" ;;   # UNVERIFIED name-only match
    2) REDIS_STATUS_CLASS="ok"   ;;   # HEALTH EVIDENCE GOOD
    3) REDIS_STATUS_CLASS="err"  ;;   # INVESTIGATION REQUIRED
    4) REDIS_STATUS_CLASS="crit" ;;   # NO READY ENDPOINTS
    *) REDIS_STATUS_CLASS="warn" ;;
esac

# --- Precompute Performance / Slowness Indicators summary stats ---
if [ "$API_LATENCY_MS" -ge "$API_LATENCY_CRIT_MS" ] 2>/dev/null; then
    API_LATENCY_CLASS="crit"
elif [ "$API_LATENCY_MS" -ge "$API_LATENCY_WARN_MS" ] 2>/dev/null; then
    API_LATENCY_CLASS="warn"
else
    API_LATENCY_CLASS="ok"
fi

if [ -z "$ETCD_PODS" ]; then
    ETCD_STATUS_TEXT="NOT VISIBLE (managed cluster or non-standard etcd)"; ETCD_STATUS_CLASS="warn"
elif [ "$ETCD_MATCH_COUNT" -gt 0 ] 2>/dev/null; then
    ETCD_STATUS_TEXT="${ETCD_MATCH_COUNT} slow-op warning(s) across ${ETCD_POD_COUNT} pod(s)"; ETCD_STATUS_CLASS="err"
else
    ETCD_STATUS_TEXT="${ETCD_POD_COUNT} pod(s) checked, clean"; ETCD_STATUS_CLASS="ok"
fi

NODE_OVERSUB_COUNT=0
if [ -s "$REPORT_DIR/data/node-oversubscription.tsv" ]; then
    NODE_OVERSUB_COUNT=$(awk -F'\t' -v c="$NODE_CPU_WARN_PCT" -v m="$NODE_MEM_WARN_PCT" '$4>=c || $7>=m' "$REPORT_DIR/data/node-oversubscription.tsv" | wc -l | tr -d ' ')
fi
if [ "$NODE_OVERSUB_COUNT" -gt 0 ] 2>/dev/null; then
    NODE_OVERSUB_CLASS="err"; NODE_OVERSUB_TEXT="${NODE_OVERSUB_COUNT} node(s) tight on requests"
else
    NODE_OVERSUB_CLASS="ok"; NODE_OVERSUB_TEXT="within limits"
fi

HPA_ISSUE_COUNT=$(awk -F'\t' '$2=="HPA_INACTIVE" || $2=="HPA_MAXED"' "$FACTS_FILE" 2>/dev/null | wc -l | tr -d ' ')
if [ "$HPA_ISSUE_COUNT" -gt 0 ] 2>/dev/null; then
    HPA_CLASS="err"; HPA_TEXT="${HPA_ISSUE_COUNT} HPA(s) inactive or maxed"
else
    HPA_CLASS="ok"; HPA_TEXT="no HPA issues found"
fi

POD_RES_ISSUE_COUNT=$(awk -F'\t' '$2=="POD_CPU_HIGH" || $2=="POD_MEM_HIGH"' "$FACTS_FILE" 2>/dev/null | wc -l | tr -d ' ')
if [ "$POD_METRICS_AVAILABLE" != "1" ]; then
    POD_RES_CLASS="warn"; POD_RES_TEXT="metrics unavailable"
elif [ "$POD_RES_ISSUE_COUNT" -gt 0 ] 2>/dev/null; then
    POD_RES_CLASS="err"; POD_RES_TEXT="${POD_RES_ISSUE_COUNT} pod(s) near CPU/memory limit"
else
    POD_RES_CLASS="ok"; POD_RES_TEXT="no pods near their limits"
fi

cat >> "$REPORT" <<EOF

====================================================================
FINAL SUMMARY
====================================================================
Context        : $CURRENT_CONTEXT
Scan window    : last ${SCAN_MINUTES} min ($SCAN_START_HUMAN -> $SCAN_END_HUMAN)
Scope          : $(scope_description)
Search         : ${SEARCH_VALUE:-<full scan>}  (sources: $MATCHES, occurrences: $SEARCH_OCCURRENCES, resources: $SEARCH_RESOURCES, namespaces: $SEARCH_NAMESPACES)
Control plane  : $CONTROL_PLANE_STATUS
Redis          : $REDIS_STATUS
Critical       : $CRITICAL
Errors         : $ERRORS
Warnings       : $WARNINGS
Info           : $INFO
EOF

cat >> "$FIX_REPORT" <<'EOF'

====================================================================
GENERAL READ-ONLY TROUBLESHOOTING COMMANDS (none executed by scanner)
====================================================================
kubectl describe node <node>
kubectl describe pod <pod> -n <namespace>
kubectl logs <pod> -n <namespace> -c <container> --since=1h --timestamps
kubectl logs <pod> -n <namespace> -c <container> --previous --timestamps
kubectl describe svc <service> -n <namespace>
kubectl get endpoints <service> -n <namespace>
kubectl get endpointslices -n <namespace>
kubectl get networkpolicy -A
kubectl top nodes
kubectl top pods -A
kubectl get pvc -A
====================================================================
IMPORTANT: This scanner is diagnostic only. It never executes
remediation, restarts, scaling, or any state-changing command.
====================================================================
EOF

# --- Escape all dynamic values before they go into HTML. SEARCH_VALUE in
# particular is user-controlled input, so it must never be interpolated
# into HTML unescaped. ---
HTML_CONTEXT=$(printf '%s' "$CURRENT_CONTEXT" | html_escape)
HTML_SEARCH=$(printf '%s' "${SEARCH_VALUE:-Full scan}" | html_escape)
HTML_SCOPE=$(printf '%s' "$(scope_description)" | html_escape)

# --- Build a self-contained HTML report ---
{
cat <<HTML_HEAD
<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>K8s Incident Report - $HTML_CONTEXT</title>
<style>
body{font-family:-apple-system,Segoe UI,Arial,sans-serif;background:#0f1115;color:#e6e6e6;margin:0;padding:24px;}
h1{margin-top:0} h2{border-bottom:1px solid #333;padding-bottom:6px;margin-top:32px}
.card{background:#1a1d24;border:1px solid #2a2d36;border-radius:8px;padding:16px;margin:10px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.stat{font-size:28px;font-weight:bold} .label{color:#9aa0aa;font-size:12px;text-transform:uppercase}
.crit{color:#ff5c5c}.err{color:#ff8c42}.warn{color:#ffd166}.ok{color:#06d6a0}
pre{background:#0b0d11;border:1px solid #2a2d36;border-radius:6px;padding:12px;overflow-x:auto;white-space:pre-wrap;font-size:12px}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:12px;margin-left:8px}
.badge.crit{background:#3a1414}.badge.err{background:#3a2414}.badge.warn{background:#3a3414}.badge.ok{background:#123a2c}
table{font-size:13px} th{color:#9aa0aa;font-weight:600}
.timeline{position:relative;margin-left:12px;padding-left:20px;border-left:2px solid #2a2d36}
.tl-item{position:relative;margin-bottom:14px}
.tl-item::before{content:"";position:absolute;left:-26px;top:4px;width:10px;height:10px;border-radius:50%;background:#555}
.tl-item.crit::before{background:#ff5c5c} .tl-item.err::before{background:#ff8c42} .tl-item.warn::before{background:#ffd166}
.tl-time{color:#9aa0aa;font-size:12px;margin-right:8px}
</style></head><body>
<h1>Kubernetes Incident Diagnostic Report</h1>
<div class="card">
<div class="grid">
<div><div class="label">Context</div><div class="stat" style="font-size:16px">$HTML_CONTEXT</div></div>
<div><div class="label">Scan window</div><div class="stat" style="font-size:16px">${SCAN_MINUTES} min</div></div>
<div><div class="label">Scope</div><div class="stat" style="font-size:14px">$HTML_SCOPE</div></div>
<div><div class="label">From</div><div class="stat" style="font-size:14px">$SCAN_START_HUMAN</div></div>
<div><div class="label">To</div><div class="stat" style="font-size:14px">$SCAN_END_HUMAN</div></div>
<div><div class="label">Search</div><div class="stat" style="font-size:14px">$HTML_SEARCH</div></div>
<div><div class="label">Occurrences</div><div class="stat">$SEARCH_OCCURRENCES</div></div>
<div><div class="label">Resources hit</div><div class="stat" style="font-size:16px">$SEARCH_RESOURCES</div></div>
<div><div class="label">Namespaces hit</div><div class="stat" style="font-size:16px">$SEARCH_NAMESPACES</div></div>
</div>
</div>


<div class="card">
<div class="grid">
<div><div class="label">Critical</div><div class="stat crit">$CRITICAL</div></div>
<div><div class="label">Errors</div><div class="stat err">$ERRORS</div></div>
<div><div class="label">Warnings</div><div class="stat warn">$WARNINGS</div></div>
<div><div class="label">Info</div><div class="stat ok">$INFO</div></div>
</div>
</div>

<div class="card">
<h2 style="margin-top:0;border:none">Status Overview</h2>
<div class="grid">
<div>Control plane <span class="badge $([ "$CONTROL_PLANE_STATUS" = HEALTHY ] && echo ok || echo err)">$CONTROL_PLANE_STATUS</span></div>
<div>Redis <span class="badge $REDIS_STATUS_CLASS">$REDIS_STATUS</span></div>
<div>CoreDNS <span class="badge $([ "$COREDNS_STATE" = HEALTHY ] && echo ok || echo warn)">$COREDNS_STATE</span></div>
<div>Endpoint probes <span class="badge $PROBE_STATUS_CLASS">$PROBE_STATUS_TEXT</span></div>
<div>F5 / external LB <span class="badge $F5_STATUS_CLASS">$F5_STATUS_TEXT</span></div>
<div>API server latency <span class="badge $API_LATENCY_CLASS">${API_LATENCY_MS}ms</span></div>
</div>
</div>

<div class="card">
<h2 style="margin-top:0;border:none">Performance / Slowness Indicators</h2>
<p style="color:#9aa0aa;font-size:13px">Circumstantial evidence toward common INFRASTRUCTURE-side causes of "the app works but is slow". This cannot diagnose a slow application request path itself (a slow SQL query, a slow third-party call, slow app code) -- that needs distributed tracing or an APM this scanner has no access to. Treat everything here as "rule this in or out", not a confirmed diagnosis, especially the single-sample API latency reading below.</p>
<div class="grid">
<div>etcd <span class="badge $ETCD_STATUS_CLASS">$ETCD_STATUS_TEXT</span></div>
<div>Node requests vs. allocatable <span class="badge $NODE_OVERSUB_CLASS">$NODE_OVERSUB_TEXT</span></div>
<div>HPA (autoscaling) <span class="badge $HPA_CLASS">$HPA_TEXT</span></div>
<div>Pod CPU/memory vs. limits <span class="badge $POD_RES_CLASS">$POD_RES_TEXT</span></div>
<div>CPU throttling <span class="badge warn">NOT DETECTABLE (needs Prometheus)</span></div>
</div>
</div>
HTML_HEAD

if [ -n "$SEARCH_VALUE" ] && [ -s "$MATCH_REPORT" ]; then
    echo '<h2>Search Matches (with context)</h2>'
    echo '<p style="color:#9aa0aa;font-size:13px">Occurrences of your search term are highlighted <mark style="background:#ffd166;color:#0f1115;padding:0 2px;border-radius:2px;">like this</mark>.</p>'
    echo '<div class="card"><pre>'
    # Highlight is applied AFTER html-escaping, using awk's index()/substr()
    # for a purely literal (non-regex) substring replace -- the search term
    # can contain any characters (., *, [, etc.) without needing regex
    # escaping, consistent with how the search itself uses grep -F. The
    # term used for matching is escaped with the SAME html_escape() as the
    # surrounding text, so it correctly finds itself inside already-escaped
    # content (e.g. searching for "a&b" must match the "a&amp;b" that's
    # actually in the escaped stream).
    HTML_SEARCH_TERM=$(printf '%s' "$SEARCH_VALUE" | html_escape)
    sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' "$MATCH_REPORT" | \
        awk -v term="$HTML_SEARCH_TERM" '
        {
            line = $0
            tlen = length(term)
            if (tlen == 0) { print line; next }
            result = ""
            while ((idx = index(line, term)) > 0) {
                result = result substr(line, 1, idx-1) "<mark style=\"background:#ffd166;color:#0f1115;padding:0 2px;border-radius:2px;\">" substr(line, idx, tlen) "</mark>"
                line = substr(line, idx + tlen)
            }
            print result line
        }'
    echo '</pre></div>'
fi

# --- Incident timeline: chronological view of everything flagged, built
# from the same warn/error/critical calls made throughout the scan. Times
# are scan-machine UTC (kubectl-reported event/log timestamps are shown
# per-item in the Error Catalog below; this view is for at-a-glance shape
# of the incident, not authoritative per-event time). ---
echo "<h2>Node Resource Requests vs. Allocatable</h2>"
echo '<p style="color:#9aa0aa;font-size:13px">Sum of declared container resource REQUESTS on each node, compared to that node'\''s allocatable capacity -- not live usage (see kubectl top for that). A node near 100% here has little scheduling headroom and is a plausible contributor to contention/slowness for everything on it, independent of what kubectl top shows at any given instant.</p>'
if [ -s "$REPORT_DIR/data/node-oversubscription.tsv" ]; then
    echo '<div class="card" style="overflow-x:auto"><table style="width:100%;border-collapse:collapse">'
    echo '<tr style="text-align:left;border-bottom:2px solid #333"><th style="padding:6px">Node</th><th style="padding:6px">CPU requested</th><th style="padding:6px">CPU %</th><th style="padding:6px">Memory requested</th><th style="padding:6px">Memory %</th></tr>'
    while IFS=$'\t' read -r node reqcpu alloccpu cpupct reqmem allocmem mempct; do
        [ -z "$node" ] && continue
        NCLASS="ok"
        { [ "$cpupct" -ge "$NODE_CPU_WARN_PCT" ] 2>/dev/null || [ "$mempct" -ge "$NODE_MEM_WARN_PCT" ] 2>/dev/null; } && NCLASS="warn"
        { [ "$cpupct" -ge "$NODE_CPU_CRIT_PCT" ] 2>/dev/null || [ "$mempct" -ge "$NODE_MEM_CRIT_PCT" ] 2>/dev/null; } && NCLASS="err"
        echo "<tr style=\"border-bottom:1px solid #2a2d36\">"
        echo "<td style=\"padding:6px\">$(echo "$node" | html_escape)</td>"
        echo "<td style=\"padding:6px\">${reqcpu}m / ${alloccpu}m</td>"
        echo "<td style=\"padding:6px\"><span class=\"badge $NCLASS\">${cpupct}%</span></td>"
        echo "<td style=\"padding:6px\">${reqmem}Mi / ${allocmem}Mi</td>"
        echo "<td style=\"padding:6px\"><span class=\"badge $NCLASS\">${mempct}%</span></td>"
        echo "</tr>"
    done < "$REPORT_DIR/data/node-oversubscription.tsv"
    echo '</table></div>'
else
    echo '<div class="card">No node resource data collected.</div>'
fi

echo "<h2>Pod Resource Usage (CPU / Memory)</h2>"
echo '<p style="color:#9aa0aa;font-size:13px">Live usage (from Metrics Server) for every pod covered by this scan, cross-referenced against that pod'\''s own declared requests and limits -- a raw usage number means little without knowing what the pod is actually allowed to use. "no limit" means the container has none set: it cannot be throttled/OOMKilled by its own limit, but it is also an unbounded stability risk for its node neighbors.</p>'
if [ "$POD_METRICS_AVAILABLE" != "1" ]; then
    echo '<div class="card">Metrics Server data unavailable for this run -- per-pod usage could not be collected.</div>'
elif [ -s "$REPORT_DIR/data/pod-resource-usage.tsv" ]; then
    echo '<div class="card" style="overflow-x:auto"><table style="width:100%;border-collapse:collapse">'
    echo '<tr style="text-align:left;border-bottom:2px solid #333"><th style="padding:6px">Namespace / Pod</th><th style="padding:6px">CPU usage</th><th style="padding:6px">CPU request / limit</th><th style="padding:6px">CPU % of limit</th><th style="padding:6px">Mem usage</th><th style="padding:6px">Mem request / limit</th><th style="padding:6px">Mem % of limit</th></tr>'
    while IFS=$'\t' read -r ns pod usagecpu reqcpu limcpu cpupct usagemem reqmem limmem mempct; do
        [ -z "$pod" ] && continue
        CCLASS="ok"
        [ "$cpupct" != "n/a" ] && [ "$cpupct" -ge "$POD_CPU_WARN_PCT" ] 2>/dev/null && CCLASS="warn"
        [ "$cpupct" != "n/a" ] && [ "$cpupct" -ge "$POD_CPU_CRIT_PCT" ] 2>/dev/null && CCLASS="err"
        MCLASS="ok"
        [ "$mempct" != "n/a" ] && [ "$mempct" -ge "$POD_MEM_WARN_PCT" ] 2>/dev/null && MCLASS="warn"
        [ "$mempct" != "n/a" ] && [ "$mempct" -ge "$POD_MEM_CRIT_PCT" ] 2>/dev/null && MCLASS="err"
        LIMCPU_DISP="${limcpu}m"; [ "$limcpu" = "0" ] && LIMCPU_DISP="no limit"
        LIMMEM_DISP="${limmem}Mi"; [ "$limmem" = "0" ] && LIMMEM_DISP="no limit"
        echo "<tr style=\"border-bottom:1px solid #2a2d36\">"
        echo "<td style=\"padding:6px\">$(echo "$ns/$pod" | html_escape)</td>"
        echo "<td style=\"padding:6px\">${usagecpu}m</td>"
        echo "<td style=\"padding:6px\">${reqcpu}m / $(echo "$LIMCPU_DISP" | html_escape)</td>"
        echo "<td style=\"padding:6px\"><span class=\"badge $CCLASS\">$(echo "$cpupct" | html_escape)$([ "$cpupct" != "n/a" ] && echo "%")</span></td>"
        echo "<td style=\"padding:6px\">${usagemem}Mi</td>"
        echo "<td style=\"padding:6px\">${reqmem}Mi / $(echo "$LIMMEM_DISP" | html_escape)</td>"
        echo "<td style=\"padding:6px\"><span class=\"badge $MCLASS\">$(echo "$mempct" | html_escape)$([ "$mempct" != "n/a" ] && echo "%")</span></td>"
        echo "</tr>"
    done < "$REPORT_DIR/data/pod-resource-usage.tsv"
    echo '</table></div>'
else
    echo '<div class="card">No pods with matching metrics data were found in this scan'\''s scope.</div>'
fi

echo "<h2>Service Topology -- Service &rarr; ClusterIP &rarr; Endpoints (Ready / Not-Ready)</h2>"
echo '<p style="color:#9aa0aa;font-size:13px">Built from EndpointSlices (falls back to legacy Endpoints if no slice exists). Each endpoint shows the backing pod name from targetRef, so you can see exactly which pod is or is not serving traffic for a service.</p>'
if [ -s "$REPORT_DIR/data/service-topology.tsv" ]; then
    echo '<div class="card" style="overflow-x:auto"><table style="width:100%;border-collapse:collapse">'
    echo '<tr style="text-align:left;border-bottom:2px solid #333"><th style="padding:6px">Namespace</th><th style="padding:6px">Service</th><th style="padding:6px">ClusterIP</th><th style="padding:6px">Ready endpoints</th><th style="padding:6px">Not-Ready endpoints</th></tr>'
    while IFS='|' read -r ns svc cip ready notready; do
        [ -z "$svc" ] && continue
        RCLASS="ok"; [ -z "$ready" ] && RCLASS="crit"
        NCLASS=""; [ -n "$notready" ] && NCLASS="warn"
        if [ -n "$notready" ]; then
            NOTREADY_CELL="<span class=\"badge $NCLASS\">$(echo "$notready" | html_escape)</span>"
        else
            NOTREADY_CELL="--"
        fi
        echo "<tr style=\"border-bottom:1px solid #2a2d36\">"
        echo "<td style=\"padding:6px\">$(echo "$ns" | html_escape)</td>"
        echo "<td style=\"padding:6px\">$(echo "$svc" | html_escape)</td>"
        echo "<td style=\"padding:6px\">$(echo "$cip" | html_escape)</td>"
        echo "<td style=\"padding:6px\"><span class=\"badge $RCLASS\">$([ -n "$ready" ] && echo "$ready" | html_escape || echo NONE)</span></td>"
        echo "<td style=\"padding:6px\">$NOTREADY_CELL</td>"
        echo "</tr>"
    done < <(awk -F'\t' '{print $1"|"$2"|"$3"|"$4"|"$5}' "$REPORT_DIR/data/service-topology.tsv")
    echo '</table></div>'
else
    echo '<div class="card">No services found in scanned namespaces.</div>'
fi

echo "<h2>Active Endpoint Probes (opt-in live GET check)</h2>"
if [ "$ENABLE_ENDPOINT_PROBE" != "1" ]; then
    echo '<div class="card">Disabled for this run. Set <code>ENABLE_ENDPOINT_PROBE=1</code> (optionally with <code>PROBE_PATH</code>, <code>PROBE_TIMEOUT</code>, <code>PROBE_PORT_OVERRIDE</code>) to have the scanner issue a live GET -- via <code>kubectl exec</code> into each endpoint pod'\''s own container -- at <code>127.0.0.1:&lt;port&gt;PROBE_PATH</code>. This confirms the app actually answers, not just that Kubernetes reports it Ready. It proves local responsiveness only, not cross-node/NetworkPolicy reachability, and issues GET requests only -- no Kubernetes object is ever changed.</div>'
elif [ -s "$PROBE_TSV" ]; then
    echo '<p style="color:#9aa0aa;font-size:13px">Each row is one live GET issued from inside that pod'\''s own container to its own loopback address -- it proves the app process answers locally, not that other pods can reach it over the network.</p>'
    echo '<div class="card" style="overflow-x:auto"><table style="width:100%;border-collapse:collapse">'
    echo '<tr style="text-align:left;border-bottom:2px solid #333"><th style="padding:6px">Result</th><th style="padding:6px">Namespace</th><th style="padding:6px">Pod/Container</th><th style="padding:6px">Port</th><th style="padding:6px">Service</th><th style="padding:6px">Endpoint state</th><th style="padding:6px">Detail</th></tr>'
    while IFS=$'\t' read -r st ns podc port svc label detail; do
        [ -z "$st" ] && continue
        CLASS="ok"
        case "$st" in FAIL) CLASS="crit" ;; WARN) CLASS="warn" ;; SKIP) CLASS="warn" ;; OK) CLASS="ok" ;; esac
        echo "<tr style=\"border-bottom:1px solid #2a2d36\">"
        echo "<td style=\"padding:6px\"><span class=\"badge $CLASS\">$(echo "$st" | html_escape)</span></td>"
        echo "<td style=\"padding:6px\">$(echo "$ns" | html_escape)</td>"
        echo "<td style=\"padding:6px\">$(echo "$podc" | html_escape)</td>"
        echo "<td style=\"padding:6px\">$(echo "$port" | html_escape)</td>"
        echo "<td style=\"padding:6px\">$(echo "$svc" | html_escape)</td>"
        echo "<td style=\"padding:6px\">$(echo "$label" | html_escape)</td>"
        echo "<td style=\"padding:6px\">$(echo "$detail" | html_escape)</td>"
        echo "</tr>"
    done < "$PROBE_TSV"
    echo '</table></div>'
else
    echo '<div class="card">Enabled, but nothing was probed this run (no EndpointSlice-backed services with resolvable pods were found).</div>'
fi

echo "<h2>F5 / External Load Balancer</h2>"
if [ -z "$F5_LOG_SOURCE" ] && [ -z "$F5_LOG_HOOK" ]; then
    echo '<div class="card">Not configured for this run. Set <code>F5_LOG_SOURCE</code> (a file or directory of already-exported F5 logs) and/or <code>F5_LOG_HOOK</code> (an executable this scanner runs and reads stdout from) to fold F5/WAF findings -- blocked requests, pool member down, expired monitors, iRule drops, etc -- into this report. This scanner has no direct network access to any external appliance; it only reads what you point it at.</div>'
elif [ "$F5_MATCHES_COUNT" -gt 0 ] 2>/dev/null; then
    echo "<div class=\"card\"><p><b>$F5_MATCHES_COUNT matching line(s)</b> found against the configured F5_BLOCK_PATTERN. Full matched lines (redacted) are included in the Errors and Warnings section below, and the top match is folded into Root Cause Analysis and the Error Catalog as category <b>F5_BLOCKED</b>, owner <b>Network team</b>.</p></div>"
else
    echo '<div class="card">F5 log source configured and ingested -- no lines matched F5_BLOCK_PATTERN in this scan window.</div>'
fi

echo "<h2>Incident Timeline (scan order, UTC)</h2>"
if [ -s "$TIMELINE_FILE" ]; then
    echo '<div class="card"><div class="timeline">'
    sort -t$'\t' -k1,1 "$TIMELINE_FILE" | while IFS=$'\t' read -r ttime tsev tmsg; do
        [ -z "$ttime" ] && continue
        CLASS="warn"
        case "$tsev" in CRITICAL) CLASS="crit" ;; ERROR) CLASS="err" ;; WARNING) CLASS="warn" ;; esac
        echo "<div class=\"tl-item $CLASS\"><span class=\"tl-time\">$(echo "$ttime" | html_escape) UTC</span><span class=\"badge $CLASS\">$(echo "$tsev" | html_escape)</span> $(echo "$tmsg" | html_escape)</div>"
    done
    echo '</div></div>'
else
    echo '<div class="card">No warnings/errors were flagged during this scan window.</div>'
fi

echo "<h2>Root Cause Analysis ($ROOT_CAUSE_COUNT candidate(s))</h2>"
echo '<p style="color:#9aa0aa;font-size:13px">Evidence-based correlation across the resources touched during this scan. These are ranked "investigation leads" based on how upstream a finding typically is -- not proven causation. Always confirm with the suggested read-only commands before acting.</p>'
cat "$ROOTCAUSE_HTML"

echo "<h2>Error Catalog -- every finding ($CATALOG_COUNT), by pod &amp; timestamp</h2>"
echo '<p style="color:#9aa0aa;font-size:13px">Every individual error/warning detected in this scan window, with the exact pod/container, when it happened (log timestamp when available, else scan time), which team likely owns the fix, and the read-only command(s) to confirm before acting.</p>'
echo '<div class="card" style="overflow-x:auto">'
cat "$CATALOG_HTML"
echo '</div>'

ERROR_REPORT_LINES=$(wc -l < "$ERROR_REPORT" 2>/dev/null | tr -d ' ')
echo "<h2>Errors and Warnings -- full, untruncated (${ERROR_REPORT_LINES:-0} lines)</h2>"
echo '<p style="color:#9aa0aa;font-size:13px">This is the complete content matched during the scan -- not an excerpt -- so nothing needed for debugging is cut. Also available as a plain text file at errors-and-warnings.txt inside the report directory.</p>'
echo '<div class="card"><pre>'
sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' "$ERROR_REPORT"
echo '</pre></div>'

echo '<h2>Recommended Investigation Commands (none executed)</h2><div class="card"><pre>'
sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' "$FIX_REPORT"
echo '</pre></div>'

cat <<HTML_TAIL
<h2>Safety Confirmation</h2>
<div class="card"><pre>
Kubernetes resources modified/created/deleted : NO
Pods restarted / nodes drained or cordoned    : NO
kubectl exec diagnostics enabled              : $([ "$ENABLE_POD_NETWORK_TEST" = "1" ] && echo YES || echo "NO (default off)")
Endpoint GET probes issued (opt-in)           : $([ "$ENABLE_ENDPOINT_PROBE" = "1" ] && echo "YES ($PROBE_TOTAL probe(s), GET only, no Kubernetes object changed)" || echo "NO (default off)")
F5/external log hook executed (opt-in)        : $([ -n "$F5_LOG_HOOK" ] && echo "YES ($F5_LOG_HOOK -- must be read-only by design of the hook itself; this scanner only reads its stdout)" || echo "NO")
Automatic remediation                         : NEVER
Public internet access required               : NO (still requires connectivity to the Kubernetes API server via kubeconfig)
Report written locally to                     : $REPORT_DIR/
</pre></div>

<h2>Coverage Limitations</h2>
<div class="card"><pre>
24h application/container logs   : available via --since=${SCAN_MINUTES}m
Kubernetes Events                : subject to cluster's event retention window
24h kubelet / kernel / node logs : NOT available via Kubernetes API alone (needs node/SSH or external logging)
Network blocking (NetworkPolicy) : evidence only (endpoints/logs), not packet-level proof
F5 / external LB / WAF           : NOT visible to this scanner directly -- only via the pluggable F5_LOG_SOURCE / F5_LOG_HOOK hook (opt-in, off unless configured)
Endpoint probe reachability      : when enabled, probes are loopback-only (inside the pod's own container) -- proves the app answers locally, not that other pods/nodes/NetworkPolicy allow reaching it
Snapshot timing                  : each check is a separate live kubectl call made a moment apart, not one atomic snapshot -- during a rapidly changing/flapping incident, two different checks can in principle reflect slightly different instants. When two sections disagree, trust the most specific, most recent evidence (a pod's own Ready condition, live logs) over aggregate summaries.
Root-cause grouping               : candidates are grouped by the resolved owning workload (Deployment/StatefulSet/Job, via ownerReferences), not just by namespace, so unrelated incidents in the same namespace are kept as separate candidates. Remaining edge cases: a bare pod with no owner reference is its own group; a Service with endpoints is grouped with the workload behind those endpoints; a Service with ZERO endpoints has no pod to resolve from and is intentionally left isolated (that absence is itself the finding). Two genuinely distinct workloads that happen to share an identical name across different resource kinds in the same namespace are a residual, unlikely edge case not disambiguated further.
"App works but is slow" diagnosis : this scanner can only rule common INFRASTRUCTURE-side causes in or out (control plane/etcd latency, node oversubscription, HPA capacity) -- it cannot diagnose a slow application request path (slow SQL, slow third-party call, slow app code), since Kubernetes exposes no per-request latency data and this scanner has no tracing/APM access. If all four Performance indicators are clean, the slowness is very likely inside the application or a dependency it calls, not the cluster.
API server latency                : a SINGLE-SAMPLE reading taken once during this run, not a trend -- a one-off network blip can false-positive and a real but intermittent slowdown can be missed entirely if it isn't happening at the exact moment this scan runs. Corroborate with the etcd check and repeat runs before treating as a confirmed root cause.
etcd health                       : best-effort and visible ONLY on kubeadm-style clusters running etcd as a static pod in kube-system. Managed clusters (EKS, GKE, AKS) run etcd outside Kubernetes entirely -- "not detected" there is expected, not a failed check.
Node oversubscription             : computed from declared resource REQUESTS, not live usage -- a node can show high % here while kubectl top shows it mostly idle (over-requested but under-used), or vice versa (under-requested but a burst of real usage). Both readings are meaningful; neither alone is the full picture.
CPU throttling                    : NOT detectable by this scanner. A container hitting its CPU limit and being throttled is invisible to both 'kubectl top' and the metrics-server API -- that data (container_cpu_cfs_throttled_*) only exists in cAdvisor/Prometheus, which this scanner does not query. This is the single most common invisible-to-this-tool cause of "slow but not crashing".
Pod CPU/memory usage              : a SINGLE-SAMPLE reading from Metrics Server at scan time, not a trend -- a pod that briefly spikes to 95% of its limit moments before or after this scan runs will not be caught, and a pod caught mid-spike may look worse than its typical behavior. High usage vs. limit is a leading indicator, not a confirmed diagnosis; corroborate with repeat runs, or run 'kubectl top pod --containers' several times a few seconds apart, or use a monitoring system for a real trend.
</pre></div>

</body></html>
HTML_TAIL
} > "$HTML_REPORT"

cat > "$REPORT_DIR/README.txt" <<EOF
Kubernetes Incident Diagnostic Report
Context   : $CURRENT_CONTEXT
Generated : $(timestamp)
Window    : last ${SCAN_MINUTES} min ($SCAN_START_HUMAN -> $SCAN_END_HUMAN)
Scope     : $(scope_description)
Search    : ${SEARCH_VALUE:-<full scan>}  (sources: $MATCHES, occurrences: $SEARCH_OCCURRENCES, resources: $SEARCH_RESOURCES, namespaces: $SEARCH_NAMESPACES)

Open index.html in a browser for the visual report (fully offline, no
network access needed).

Text reports:
  $REPORT
  $ERROR_REPORT
  $FIX_REPORT
  $MATCH_REPORT       (only populated if a search value was given)
  $ROOTCAUSE_REPORT   (ranked root-cause candidates with evidence + commands)

Summary:
  Critical           : $CRITICAL
  Errors             : $ERRORS
  Warnings           : $WARNINGS
  Info               : $INFO
  Root-cause candidates : $ROOT_CAUSE_COUNT

Optional capabilities (all OFF unless explicitly enabled):
  Endpoint probes (ENABLE_ENDPOINT_PROBE=1) : $([ "$ENABLE_ENDPOINT_PROBE" = "1" ] && echo "ON -- $PROBE_TOTAL probed, $PROBE_FAIL_COUNT failed" || echo "off")
  F5/external LB hook (F5_LOG_SOURCE/F5_LOG_HOOK) : $([ -n "$F5_LOG_SOURCE$F5_LOG_HOOK" ] && echo "configured -- $F5_MATCHES_COUNT match(es)" || echo "not configured")

THIS SCAN IS READ-ONLY with respect to Kubernetes objects. Endpoint probes
(if enabled) issue GET requests only; the F5 hook (if configured) only
reads data you point it at. No Kubernetes resource was modified.
EOF

echo ""
echo "===================================================================="
echo "SCAN COMPLETE"
echo "===================================================================="
echo -e "${RED}Critical : $CRITICAL${NC}"
echo -e "${RED}Errors   : $ERRORS${NC}"
echo -e "${YELLOW}Warnings : $WARNINGS${NC}"
echo -e "${CYAN}Info     : $INFO${NC}"
if [ -n "$SEARCH_VALUE" ]; then
    echo "Search '$SEARCH_VALUE': $SEARCH_OCCURRENCES occurrence(s) across $MATCHES source(s), $SEARCH_RESOURCES resource(s), $SEARCH_NAMESPACES namespace(s)" | highlight_term
    if [ -s "$MATCH_REPORT" ]; then
        echo ""
        echo "--- Search match preview (first 60 lines; full file: $MATCH_REPORT) ---"
        head -60 "$MATCH_REPORT" | highlight_term
        echo "--- end of preview ---"
    fi
fi
echo "Root-cause candidates : $ROOT_CAUSE_COUNT (see $ROOTCAUSE_REPORT or index.html)"
if [ "$ENABLE_ENDPOINT_PROBE" = "1" ]; then
    echo "Endpoint probes        : $PROBE_TOTAL probed, $PROBE_FAIL_COUNT failed (see $PROBE_REPORT or index.html)"
else
    echo "Endpoint probes        : disabled (set ENABLE_ENDPOINT_PROBE=1 to enable)"
fi
if [ -n "$F5_LOG_SOURCE$F5_LOG_HOOK" ]; then
    echo "F5/external LB         : $F5_MATCHES_COUNT match(es) (see index.html)"
else
    echo "F5/external LB         : not configured (set F5_LOG_SOURCE and/or F5_LOG_HOOK to enable)"
fi
echo ""
echo "Report directory : $REPORT_DIR"
echo "HTML report       : $HTML_REPORT"
echo ""
echo "No Kubernetes resource was modified by this scan."

if should_exit_after_run; then
    echo ""
    echo "Done (non-interactive or RUN_ONCE=1 run -- not returning to the prompt)."
    exit 0
fi

echo ""
echo "===================================================================="
echo "Returning to the first question... (Ctrl+C to exit)"
echo "===================================================================="

done