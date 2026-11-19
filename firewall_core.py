import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

from ai_security import calculate_risk


RISK_THRESHOLD = 90
RULE_LIFETIME_HOURS = 24
POLL_INTERVAL_SECONDS = 5
MAX_EVENT_BATCH = 1000
MAX_EVENT_AGE = timedelta(minutes=5)
WFP_OUTBOUND_DIRECTION = "%%14593"
RULE_PREFIX = "AI_Firewall_Project_"
TASK_PREFIX = "AI_Firewall_Expire_"
RULE_GROUP = "AI Firewall Project"
CORE_PROCESS_NAMES = {
    "lsass.exe",
    "services.exe",
    "smss.exe",
    "system",
    "system idle process",
    "svchost.exe",
    "wininit.exe",
    "winlogon.exe",
}


def _run_powershell(script, timeout=30):
    if os.name != "nt":
        raise OSError("The AI firewall monitor can run only on Windows.")

    encoded_script = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            encoded_script,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"PowerShell operation failed: {detail}")
    return result.stdout.strip()


def _latest_event_record_id():
    output = _run_powershell(
        r"""
$ErrorActionPreference = 'Stop'
try {
    $event = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5156 } `
        -MaxEvents 1 -ErrorAction Stop
    [string]$event.RecordId
}
catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
        '0'
    }
    else {
        throw
    }
}
"""
    )
    return int(output or "0")


def collect_events_after(record_id):
    if isinstance(record_id, bool) or not isinstance(record_id, int) or record_id < 0:
        raise ValueError("The event record ID must be a non-negative integer.")

    script = r"""
$ErrorActionPreference = 'Stop'
$after = __RECORD_ID__
$xpath = "*[System[(EventID=5156) and (EventRecordID > $after)]]"
try {
    $items = @(Get-WinEvent -LogName 'Security' -FilterXPath $xpath `
        -MaxEvents 1001 -ErrorAction Stop)
}
catch {
    if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
        $items = @()
    }
    else {
        throw
    }
}

if ($items.Count -gt 1000) {
    throw 'More than 1000 unprocessed connection events were found; refusing to skip events.'
}

$result = foreach ($item in ($items | Sort-Object RecordId)) {
    [xml]$xml = $item.ToXml()
    $fields = @{}
    foreach ($data in $xml.Event.EventData.Data) {
        $fields[[string]$data.Name] = [string]$data.'#text'
    }

    $applicationPath = $null
    if ($fields.ProcessID -match '^(0x[0-9a-fA-F]+|\d+)$') {
        if ($fields.ProcessID -match '^0x') {
            $processId = [Convert]::ToInt32($fields.ProcessID.Substring(2), 16)
        }
        else {
            $processId = [int]$fields.ProcessID
        }
        $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
        if ($process -and $process.Path) {
            $reportedName = [IO.Path]::GetFileName([string]$fields.Application)
            $currentName = [IO.Path]::GetFileName([string]$process.Path)
            if ($reportedName -and
                [string]::Equals($reportedName, $currentName, [StringComparison]::OrdinalIgnoreCase)) {
                $applicationPath = [string]$process.Path
            }
        }
    }

    [PSCustomObject]@{
        record_id = [long]$item.RecordId
        timestamp = $item.TimeCreated.ToUniversalTime().ToString('o')
        direction = [string]$fields.Direction
        application = $applicationPath
        destination_address = [string]$fields.DestAddress
        destination_port = [string]$fields.DestPort
        protocol = [string]$fields.Protocol
    }
}

if ($null -eq $result) {
    '[]'
}
else {
    ConvertTo-Json -InputObject @($result) -Compress -Depth 4
}
""".replace("__RECORD_ID__", str(record_id))
    output = _run_powershell(script, timeout=60)
    if not output:
        return []

    events = json.loads(output)
    if isinstance(events, dict):
        events = [events]
    if not isinstance(events, list):
        raise ValueError("Windows returned an invalid connection-event response.")
    if len(events) > MAX_EVENT_BATCH:
        raise RuntimeError("The connection-event batch exceeds the supported limit.")
    return events


def validate_outbound_event(event, now=None):
    if not isinstance(event, dict):
        return None, "event is not an object"
    if event.get("direction") != WFP_OUTBOUND_DIRECTION:
        return None, "event is not an outbound connection"

    raw_record_id = event.get("record_id")
    if isinstance(raw_record_id, bool) or not (
        isinstance(raw_record_id, int)
        or isinstance(raw_record_id, str)
        and raw_record_id.isascii()
        and raw_record_id.isdecimal()
    ):
        return None, "event has no valid record ID"
    record_id = int(raw_record_id)
    if record_id <= 0:
        return None, "event has no valid record ID"

    try:
        timestamp = datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            return None, "event timestamp has no timezone"
        timestamp = timestamp.astimezone(timezone.utc)
    except (KeyError, TypeError, ValueError):
        return None, "event has no valid timestamp"
    current_time = now or datetime.now(timezone.utc)
    if current_time.tzinfo is None:
        current_time = current_time.replace(tzinfo=timezone.utc)
    age = current_time.astimezone(timezone.utc) - timestamp
    if age < timedelta(seconds=-30) or age > MAX_EVENT_AGE:
        return None, "event is outside the five-minute enforcement window"

    application = event.get("application")
    if not isinstance(application, str) or not application:
        return None, "the running executable could not be verified"
    application_path = Path(application)
    if not application_path.is_absolute() or application_path.suffix.lower() != ".exe":
        return None, "application path is not an absolute executable path"
    if not application_path.is_file():
        return None, "application executable no longer exists"
    if application_path.name.lower() in CORE_PROCESS_NAMES:
        return None, "core Windows processes are excluded from automatic blocking"

    windows_directory = os.environ.get("WINDIR", r"C:\Windows")
    try:
        if os.path.commonpath(
            [os.path.normcase(str(application_path)), os.path.normcase(windows_directory)]
        ) == os.path.normcase(windows_directory):
            return None, "executables under the Windows directory are excluded"
    except ValueError:
        return None, "application path is on a different volume from the Windows directory"

    try:
        address = ipaddress.ip_address(str(event["destination_address"]))
    except (KeyError, TypeError, ValueError):
        return None, "destination is not a valid IP address"
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    elif isinstance(address, ipaddress.IPv6Address) and address.scope_id:
        return None, "scoped IPv6 destinations are not eligible"
    if not address.is_global:
        return None, "only globally routable destination addresses are eligible"

    raw_port = event.get("destination_port")
    if isinstance(raw_port, bool) or not (
        isinstance(raw_port, int)
        or isinstance(raw_port, str)
        and raw_port.isascii()
        and raw_port.isdecimal()
    ):
        return None, "destination port is invalid"
    port = int(raw_port)
    if not 1 <= port <= 65535:
        return None, "destination port is outside the TCP/UDP port range"

    protocol_value = str(event.get("protocol", "")).upper()
    protocol = {"6": "TCP", "17": "UDP", "TCP": "TCP", "UDP": "UDP"}.get(
        protocol_value
    )
    if protocol is None:
        return None, "only TCP and UDP connections are eligible"

    return (
        {
            "record_id": record_id,
            "application": str(application_path),
            "remote_address": str(address),
            "remote_port": port,
            "protocol": protocol,
            "timestamp": timestamp.isoformat(),
        },
        "eligible outbound event",
    )


def _rule_identity(candidate):
    identity = "\n".join(
        (
            os.path.normcase(candidate["application"]),
            candidate["remote_address"],
            str(candidate["remote_port"]),
            candidate["protocol"],
        )
    )
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:24]
    return f"{RULE_PREFIX}{digest}", f"{TASK_PREFIX}{digest}"


def _create_temporary_block(candidate):
    rule_name, task_name = _rule_identity(candidate)
    payload = base64.b64encode(
        json.dumps(
            {
                "application": candidate["application"],
                "remote_address": candidate["remote_address"],
                "remote_port": candidate["remote_port"],
                "protocol": candidate["protocol"],
            }
        ).encode("utf-8")
    ).decode("ascii")
    script = r"""
$ErrorActionPreference = 'Stop'
$payloadBytes = [Convert]::FromBase64String('__PAYLOAD__')
$payload = [Text.Encoding]::UTF8.GetString($payloadBytes) | ConvertFrom-Json
$ruleName = '__RULE_NAME__'
$taskName = '__TASK_NAME__'

$existingRule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existingRule -and $existingTask) {
    [PSCustomObject]@{ rule_name = $ruleName; created = $false } |
        ConvertTo-Json -Compress
    exit 0
}
if ($existingTask) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}
if ($existingRule) {
    Remove-NetFirewallRule -Name $ruleName
}

New-NetFirewallRule `
    -Name $ruleName `
    -DisplayName 'AI Firewall temporary outbound block' `
    -Group '__RULE_GROUP__' `
    -Direction Outbound `
    -Action Block `
    -Profile Any `
    -Program $payload.application `
    -RemoteAddress $payload.remote_address `
    -RemotePort ([int]$payload.remote_port) `
    -Protocol $payload.protocol | Out-Null

try {
    $cleanup = "Remove-NetFirewallRule -Name '$ruleName' -ErrorAction SilentlyContinue; " +
        "Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false -ErrorAction SilentlyContinue"
    $action = New-ScheduledTaskAction `
        -Execute 'PowerShell.exe' `
        -Argument ('-NoProfile -NonInteractive -Command "& { ' + $cleanup + ' }"')
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(__LIFETIME_HOURS__)
    $principal = New-ScheduledTaskPrincipal `
        -UserId 'SYSTEM' `
        -LogonType ServiceAccount `
        -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable
    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description 'Expires a temporary AI Firewall Project rule after __LIFETIME_HOURS__ hours.' `
        -Force | Out-Null
}
catch {
    Remove-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    throw
}

[PSCustomObject]@{ rule_name = $ruleName; created = $true } |
    ConvertTo-Json -Compress
""".replace("__PAYLOAD__", payload).replace("__RULE_NAME__", rule_name).replace(
        "__TASK_NAME__", task_name
    ).replace("__RULE_GROUP__", RULE_GROUP)
    script = script.replace("__LIFETIME_HOURS__", str(RULE_LIFETIME_HOURS))
    output = _run_powershell(script, timeout=60)
    try:
        result = json.loads(output)
    except json.JSONDecodeError as error:
        raise RuntimeError("Windows did not confirm the firewall rule result.") from error
    if result.get("rule_name") != rule_name:
        raise RuntimeError("Windows returned an unexpected firewall rule name.")
    return result


def evaluate_and_apply(event, risk_score):
    if isinstance(risk_score, bool) or not isinstance(risk_score, int):
        raise ValueError("The AI risk score must be an integer.")
    if not 0 <= risk_score <= 100:
        raise ValueError("The AI risk score must be between 0 and 100.")

    candidate, reason = validate_outbound_event(event)
    if candidate is None:
        return None, reason
    if risk_score < RISK_THRESHOLD:
        return None, "risk score is below the automatic-block threshold"
    result = _create_temporary_block(candidate)
    return result, "temporary outbound block applied"


def _state_path():
    root = os.environ.get("LOCALAPPDATA")
    if not root:
        root = str(Path.home() / "AppData" / "Local")
    directory = Path(root) / "AI_Firewall_Project"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / "wfp-event-cursor.json"


def _save_cursor(path, record_id):
    temporary_path = path.with_suffix(".tmp")
    temporary_path.write_text(json.dumps({"record_id": record_id}), encoding="utf-8")
    temporary_path.replace(path)


def _load_cursor(path):
    if not path.exists():
        return None
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
        record_id = state["record_id"]
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise RuntimeError(f"Could not read the event cursor at {path}.") from error
    if isinstance(record_id, bool) or not isinstance(record_id, int) or record_id < 0:
        raise RuntimeError(f"The event cursor at {path} is invalid.")
    return record_id


def _risk_input(candidate):
    return [
        {
            "direction": "outbound",
            "destination": candidate["remote_address"],
            "destination_port": candidate["remote_port"],
            "protocol": candidate["protocol"],
        }
    ]


def monitor():
    if os.name != "nt":
        raise OSError("The AI firewall monitor can run only on Windows.")
    import ctypes

    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise PermissionError("Run start_ai_firewall.ps1 from an elevated PowerShell.")

    cursor_path = _state_path()
    cursor = _load_cursor(cursor_path)
    if cursor is None:
        cursor = _latest_event_record_id()
        _save_cursor(cursor_path, cursor)
        print(
            f"AI firewall monitor started at event {cursor}; "
            "older Security events will not be replayed."
        )
    else:
        print(f"AI firewall monitor resumed after event {cursor}.")

    while True:
        events = collect_events_after(cursor)
        for event in events:
            record_id = int(event["record_id"])
            if record_id <= cursor:
                continue

            candidate, reason = validate_outbound_event(event)
            if candidate is None:
                print(f"Event {record_id} skipped: {reason}.")
                cursor = record_id
                _save_cursor(cursor_path, cursor)
                continue

            risk_score = calculate_risk(_risk_input(candidate))
            result, reason = evaluate_and_apply(event, risk_score)
            if result is None:
                print(f"Event {record_id}: risk {risk_score}; {reason}.")
            else:
                action = "created" if result["created"] else "already active"
                print(
                    f"Event {record_id}: risk {risk_score}; "
                    f"rule {result['rule_name']} {action} for "
                    f"up to {RULE_LIFETIME_HOURS} hours."
                )
            cursor = record_id
            _save_cursor(cursor_path, cursor)

        time.sleep(POLL_INTERVAL_SECONDS)


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    if arguments != ["monitor"]:
        print("Usage: python firewall_core.py monitor", file=sys.stderr)
        return 2
    try:
        monitor()
    except KeyboardInterrupt:
        print("AI firewall monitor stopped.")
        return 0
    except (OSError, PermissionError, RuntimeError, ValueError, TimeoutError) as error:
        print(f"AI firewall monitor failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
