#!/bin/bash
# Administrator-only launchd definition management. Never run the client as root.
set -euo pipefail
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

reject() { printf 'Secrets Kit boot service rejected: %s\n' "$1" >&2; exit 78; }

user_job_loaded() {
    # A missing login domain is normal before login; other query errors cannot
    # authorize a second supervisor. Never print launchctl's untrusted output.
    local domain=$1 result output
    if output=$(LC_ALL=C /bin/launchctl print "${domain}/${user_label}" 2>&1); then
        return 0
    else
        result=$?
    fi
    [[ ${result} -eq 113 ]] && return 1
    if [[ ${result} -eq 112 && ${output} == "Bad request."$'\n'"Could not find domain for user ${domain%/*}: ${uid}" ]]; then
        return 1
    fi
    reject 'cannot determine customer supervision state; no service changed'
}

system_job_loaded() {
    local result
    if /bin/launchctl print "${target}" >/dev/null 2>&1; then return 0; else result=$?; fi
    # launchctl's service-not-found result (113) means the named job is absent. Permission,
    # communication and other failures must never authorize definition removal.
    [[ ${result} -eq 113 ]] || reject 'cannot determine system job state; definition retained'
    return 1
}
[[ ${EUID} -eq 0 ]] || reject 'administrator execution is required'
[[ $(/usr/bin/uname -s) == Darwin ]] || reject 'macOS is required'
[[ $# -eq 2 ]] || reject 'usage: manage-peer-boot-service {install|uninstall} ACCOUNT'
readonly action=$1 account=$2
[[ ${action} == install || ${action} == uninstall ]] || reject 'unsupported action'
[[ ${account} =~ ^[a-zA-Z_][a-zA-Z0-9_-]*$ ]] || reject 'invalid account name'

readonly helper=/Library/PrivilegedHelperTools/net.unixwzrd.secrets-kit.boot-service
[[ $0 == "${helper}" && -f ${helper} && ! -L ${helper} ]] || reject 'use the installed root-owned helper'
for trusted in /Library /Library/PrivilegedHelperTools "${helper}" /Library/LaunchDaemons; do
    [[ ! -L ${trusted} ]] || reject 'trusted path is a symbolic link'
    [[ $(/usr/bin/stat -f '%u' "${trusted}") == 0 ]] || reject 'trusted path is not root owned'
    mode=$(/usr/bin/stat -f '%Lp' "${trusted}")
    (( (8#${mode} & 022) == 0 )) || reject 'trusted path is writable by another account'
done

uid=$(/usr/bin/id -u "${account}") || reject 'account does not exist'
if [[ ! ${uid} =~ ^[0-9]+$ ]] || (( uid < 501 )); then
    reject 'a non-system customer account is required'
fi
readonly uid
home=$(/usr/bin/dscl . -read "/Users/${account}" NFSHomeDirectory) || reject 'local account home is unavailable'
[[ ${home} == 'NFSHomeDirectory: /'* && ${home} != *$'\n'* ]] || reject 'local account home is invalid'
home=${home#NFSHomeDirectory: }
[[ -d ${home} && ! -L ${home} && ${home} != / ]] || reject 'customer home is unavailable'
[[ $(/usr/bin/stat -f '%u' "${home}") == "${uid}" ]] || reject 'customer home owner is invalid'
readonly home
readonly launcher="${home}/.local/bin/seckit"
readonly label="net.unixwzrd.secrets-kit.daemon.${uid}"
readonly target="system/${label}"
readonly definition="/Library/LaunchDaemons/${label}.plist"
readonly user_label=net.unixwzrd.secrets-kit.daemon

work=$(/usr/bin/mktemp -d /private/var/tmp/seckit-boot.XXXXXXXX) || reject 'cannot create private staging directory'
readonly work
cleanup() { /bin/rm -f "${work}/job.plist"; /bin/rmdir "${work}"; }
trap cleanup EXIT
readonly staged="${work}/job.plist"
/usr/bin/plutil -create xml1 "${staged}"
/usr/bin/plutil -insert Label -string "${label}" "${staged}"
/usr/bin/plutil -insert UserName -string "${account}" "${staged}"
/usr/bin/plutil -insert ProgramArguments -json '[]' "${staged}"
/usr/bin/plutil -insert ProgramArguments.0 -string "${launcher}" "${staged}"
/usr/bin/plutil -insert ProgramArguments.1 -string daemon "${staged}"
/usr/bin/plutil -insert ProgramArguments.2 -string run "${staged}"
/usr/bin/plutil -insert RunAtLoad -bool YES "${staged}"
/usr/bin/plutil -insert KeepAlive -json '{"SuccessfulExit":false}' "${staged}"
/usr/bin/plutil -insert ProcessType -string Standard "${staged}"
/usr/bin/plutil -insert ThrottleInterval -integer 2 "${staged}"
/usr/bin/plutil -insert EnvironmentVariables -json '{}' "${staged}"
/usr/bin/plutil -insert EnvironmentVariables.HOME -string "${home}" "${staged}"
/usr/bin/plutil -insert StandardOutPath -string /dev/null "${staged}"
/usr/bin/plutil -insert StandardErrorPath -string /dev/null "${staged}"
/usr/bin/plutil -lint "${staged}" >/dev/null

# Compare canonical plist data, not whitespace or key order. Root never accepts
# executable/configuration fields supplied by the customer or by their runtime.
definition_preexisting=0
if [[ -e ${definition} || -L ${definition} ]]; then
    definition_preexisting=1
    [[ -f ${definition} && ! -L ${definition} ]] || reject 'existing definition is unsafe'
    [[ $(/usr/bin/stat -f '%u' "${definition}") == 0 ]] || reject 'existing definition is not root owned'
    mode=$(/usr/bin/stat -f '%Lp' "${definition}")
    (( (8#${mode} & 022) == 0 )) || reject 'existing definition is writable by another account'
    [[ $(/usr/bin/plutil -convert json -o - "${definition}") == "$(/usr/bin/plutil -convert json -o - "${staged}")" ]] || reject 'existing definition does not match this account'
else
    system_job_loaded && reject 'loaded job has no matching definition; inspect manually'
    if [[ ${action} == uninstall ]]; then
        printf '%s\n' 'Secrets Kit boot service is already absent.'
        exit 0
    fi
fi

if [[ ${action} == uninstall ]]; then
    if system_job_loaded; then
        /bin/launchctl bootout "${target}" || reject 'job did not stop; definition retained'
    fi
    system_job_loaded && reject 'job remains loaded; definition retained'
    /bin/rm "${definition}"
    printf '%s\n' 'Secrets Kit boot service removed; customer runtime and state preserved.'
    exit 0
fi

[[ -f ${launcher} && -x ${launcher} && ! -L ${launcher} ]] || reject 'installed customer launcher is unavailable'
[[ $(/usr/bin/stat -f '%u' "${launcher}") == "${uid}" ]] || reject 'launcher owner does not match customer'
# Distinguish a rejected privilege-drop/deadline policy from an absent daemon.
# No customer-controlled code is run by this preflight.
/usr/bin/sudo -n -H -T 3 -u "${account}" -- /usr/bin/env -i PATH=/usr/bin:/bin /usr/bin/true || reject 'bounded customer execution is unavailable'
for domain in "user/${uid}" "gui/${uid}"; do
    user_job_loaded "${domain}" && reject 'remove the customer LaunchAgent before installing boot supervision'
done
[[ ! -e ${home}/Library/LaunchAgents/${user_label}.plist && ! -L ${home}/Library/LaunchAgents/${user_label}.plist ]] || reject 'remove the customer LaunchAgent definition first'

# Health probes execute only as the customer, with sudo's native command
# deadline. A broken or replaced customer launcher cannot hang this root helper.
customer_ping() {
    /usr/bin/sudo -n -H -T "$1" -u "${account}" -- /usr/bin/env -i HOME="${home}" PATH=/usr/bin:/bin "${launcher}" daemon ping >/dev/null 2>&1
}

wait_for_health() {
    local deadline=$((SECONDS + 30)) remaining limit
    while (( SECONDS < deadline )); do
        remaining=$((deadline - SECONDS))
        limit=3
        (( remaining >= limit )) || limit=${remaining}
        if customer_ping "${limit}"; then return 0; fi
        (( SECONDS >= deadline )) || /bin/sleep 1
    done
    return 1
}

rollback_activation() {
    # Never tear down a job that was loaded before this invocation.
    [[ ${loaded_before} -eq 0 ]] || reject 'existing boot job is not healthy; original definition retained'
    if system_job_loaded; then
        /bin/launchctl bootout "${target}" || reject 'rollback could not stop the job; definition retained'
    fi
    system_job_loaded && reject 'rollback job remains loaded; definition retained'
    if [[ ${disabled_before} -eq 1 ]]; then
        /bin/launchctl disable "${target}" || reject 'rollback could not restore disabled state; definition retained'
    fi
    if [[ ${definition_preexisting} -eq 0 ]]; then /bin/rm "${definition}"; fi
    reject 'activation did not become healthy; previous unloaded definition state restored'
}

loaded_before=0
system_job_loaded && loaded_before=1
disabled_before=0
disabled_state=$(/bin/launchctl print-disabled system) || reject 'cannot inspect disabled service state'
if /usr/bin/awk -v key="\"${label}\"" '$1 == key && $3 == "true" {found=1} END {exit !found}' <<<"${disabled_state}"; then
    disabled_before=1
fi

if ! system_job_loaded; then
    # All client execution, including this duplicate-process check, drops UID
    # first and starts with an explicit minimal environment.
    if customer_ping 3; then
        reject 'stop the detached customer daemon before installing boot supervision'
    fi
    /usr/bin/install -o root -g wheel -m 0644 "${staged}" "${definition}"
    /bin/launchctl enable "${target}" || rollback_activation
    if ! /bin/launchctl bootstrap system "${definition}"; then
        rollback_activation
    fi
fi
/bin/launchctl kickstart "${target}" || rollback_activation
wait_for_health || rollback_activation
printf '%s\n' 'Secrets Kit boot service is reachable under the customer account.'
