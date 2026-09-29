# /opt/splunk/etc/system/local/props.conf

```ini
[windows]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)(?=<Event xmlns=)
TRUNCATE = 0
MAX_EVENTS = 20000
TIME_PREFIX = TimeCreated SystemTime='
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%7N%Z
MAX_TIMESTAMP_LOOKAHEAD = 35
KV_MODE = none
REPORT-winxml_data = winxml_data_kv
EXTRACT-winxml_header = (?s)<EventID>(?<EventCode>\d+)</EventID>.*?<TimeCreated SystemTime='(?<TimeCreatedRaw>[^']+)'/>.*?<Channel>(?<Channel>[^<]+)</Channel><Computer>(?<ComputerName>[^<]+)</Computer>
EXTRACT-winxml_provider = Provider Name='(?<Provider>[^']+)'
EXTRACT-winxml_exec = Execution ProcessID='(?<ExecProcessID>\d+)' ThreadID='(?<ExecThreadID>\d+)'
EXTRACT-winxml_recid = <EventRecordID>(?<EventRecordID>\d+)</EventRecordID>
EVAL-ScriptBlockText = if(isnotnull(ScriptBlockText), replace(replace(replace(replace(ScriptBlockText, "&lt;", "<"), "&gt;", ">"), "&#39;", "'"), "&amp;", "&"), ScriptBlockText)
category = Custom
disabled = false
```

# /opt/splunk/etc/system/local/transforms.conf

```ini
[winxml_data_kv]
REGEX = (?s)<Data Name='([^']+)'>(.*?)</Data>
FORMAT = $1::$2
```

# /opt/splunk/etc/system/local/indexes.conf

```ini
[windows]
homePath = $SPLUNK_DB/windows/db
coldPath = $SPLUNK_DB/windows/colddb
thawedPath = $SPLUNK_DB/windows/thaweddb
```

# Dataset files

This dataset contains the following files:

- `windows-sysmon.log`
- `windows-security.log`
- `windows-powershell.log`
- `activemq_exploit_lockbit_ransomware.yml`

Directory:

```text
/datasets/apt_simulations/ActiveMQ_exploit_Lockbit_Ransomware/
```

# Dataset summary

- Scenario: Apache ActiveMQ exploit leading to LockBit ransomware activity
- Source dataset manifest: `activemq_exploit_lockbit_ransomware.yml`
- Recommended index: `windows`
- Recommended sourcetype for the normalized Splunk dataset: `windows`


```

# Recommended monitor stanzas

```ini
[monitor:///attack_data/datasets/apt_simulations/ActiveMQ_exploit_Lockbit_Ransomware/windows-sysmon.log]
disabled = false
index = windows
sourcetype = windows

[monitor:///attack_data/datasets/apt_simulations/ActiveMQ_exploit_Lockbit_Ransomware/windows-security.log]
disabled = false
index = windows
sourcetype = windows

[monitor:///attack_data/datasets/apt_simulations/ActiveMQ_exploit_Lockbit_Ransomware/windows-powershell.log]
disabled = false
index = windows
sourcetype = windows
```

# Notes

- The raw source files are XML Windows Event logs.
- The `props.conf` and `transforms.conf` settings above normalize the events into a single searchable `windows` sourcetype with extracted fields such as `EventCode`, `ComputerName`, `Channel`, `Provider`, and all XML `<Data Name='...'>` pairs.
- `TRUNCATE = 0` is used to avoid breaking long Windows XML events.

# Ingest Data in Splunk

## Create `indexes.conf`

```bash
sudo tee /opt/splunk/etc/system/local/indexes.conf > /dev/null <<'EOF'
[windows]
homePath = $SPLUNK_DB/windows/db
coldPath = $SPLUNK_DB/windows/colddb
thawedPath = $SPLUNK_DB/windows/thaweddb
EOF
```

## Create `props.conf`

```bash
sudo tee /opt/splunk/etc/system/local/props.conf > /dev/null <<'EOF'
[windows]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)(?=<Event xmlns=)
TRUNCATE = 0
MAX_EVENTS = 20000
TIME_PREFIX = TimeCreated SystemTime='
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%7N%Z
MAX_TIMESTAMP_LOOKAHEAD = 35
KV_MODE = none
REPORT-winxml_data = winxml_data_kv
EXTRACT-winxml_header = (?s)<EventID>(?<EventCode>\d+)</EventID>.*?<TimeCreated SystemTime='(?<TimeCreatedRaw>[^']+)'/>.*?<Channel>(?<Channel>[^<]+)</Channel><Computer>(?<ComputerName>[^<]+)</Computer>
EXTRACT-winxml_provider = Provider Name='(?<Provider>[^']+)'
EXTRACT-winxml_exec = Execution ProcessID='(?<ExecProcessID>\d+)' ThreadID='(?<ExecThreadID>\d+)'
EXTRACT-winxml_recid = <EventRecordID>(?<EventRecordID>\d+)</EventRecordID>
EVAL-ScriptBlockText = if(isnotnull(ScriptBlockText), replace(replace(replace(replace(ScriptBlockText, "&lt;", "<"), "&gt;", ">"), "&#39;", "'"), "&amp;", "&"), ScriptBlockText)
category = Custom
disabled = false
EOF
```

## Create `transforms.conf`

```bash
sudo tee /opt/splunk/etc/system/local/transforms.conf > /dev/null <<'EOF'
[winxml_data_kv]
REGEX = (?s)<Data Name='([^']+)'>(.*?)</Data>
FORMAT = $1::$2
EOF
```

## Create `inputs.conf`

```bash
sudo tee /opt/splunk/etc/system/local/inputs.conf > /dev/null <<'EOF'
[monitor:///attack_data/datasets/apt_simulations/ActiveMQ_exploit_Lockbit_Ransomware/windows-sysmon.log]
disabled = false
index = windows
sourcetype = windows

[monitor:///attack_data/datasets/apt_simulations/ActiveMQ_exploit_Lockbit_Ransomware/windows-security.log]
disabled = false
index = windows
sourcetype = windows

[monitor:///attack_data/datasets/apt_simulations/ActiveMQ_exploit_Lockbit_Ransomware/windows-powershell.log]
disabled = false
index = windows
sourcetype = windows
EOF
```

## Restart Splunk

```bash
sudo /opt/splunk/bin/splunk restart
```

## Validate the index exists

```bash
/opt/splunk/bin/splunk list index windows -auth admin:Changeme123!
```

## Quick search validation

```bash
/opt/splunk/bin/splunk search 'search index=windows sourcetype=windows | stats count by source' -auth admin:Changeme123!
```

## Docker-based reference commands

If Splunk is running in Docker as container `splunk`:

```bash
docker exec -i splunk sh -c "cat > /opt/splunk/etc/system/local/indexes.conf" <<'EOF'
[windows]
homePath = $SPLUNK_DB/windows/db
coldPath = $SPLUNK_DB/windows/colddb
thawedPath = $SPLUNK_DB/windows/thaweddb
EOF
```

```bash
docker exec -i splunk sh -c "cat > /opt/splunk/etc/system/local/props.conf" <<'EOF'
[windows]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)(?=<Event xmlns=)
TRUNCATE = 0
MAX_EVENTS = 20000
TIME_PREFIX = TimeCreated SystemTime='
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%7N%Z
MAX_TIMESTAMP_LOOKAHEAD = 35
KV_MODE = none
REPORT-winxml_data = winxml_data_kv
EXTRACT-winxml_header = (?s)<EventID>(?<EventCode>\d+)</EventID>.*?<TimeCreated SystemTime='(?<TimeCreatedRaw>[^']+)'/>.*?<Channel>(?<Channel>[^<]+)</Channel><Computer>(?<ComputerName>[^<]+)</Computer>
EXTRACT-winxml_provider = Provider Name='(?<Provider>[^']+)'
EXTRACT-winxml_exec = Execution ProcessID='(?<ExecProcessID>\d+)' ThreadID='(?<ExecThreadID>\d+)'
EXTRACT-winxml_recid = <EventRecordID>(?<EventRecordID>\d+)</EventRecordID>
EVAL-ScriptBlockText = if(isnotnull(ScriptBlockText), replace(replace(replace(replace(ScriptBlockText, "&lt;", "<"), "&gt;", ">"), "&#39;", "'"), "&amp;", "&"), ScriptBlockText)
category = Custom
disabled = false
EOF
```

```bash
docker exec -i splunk sh -c "cat > /opt/splunk/etc/system/local/transforms.conf" <<'EOF'
[winxml_data_kv]
REGEX = (?s)<Data Name='([^']+)'>(.*?)</Data>
FORMAT = $1::$2
EOF
```

```bash
docker exec -i splunk sh -c "cat > /opt/splunk/etc/system/local/inputs.conf" <<'EOF'
[monitor:///attack_data/datasets/apt_simulations/ActiveMQ_exploit_Lockbit_Ransomware/windows-sysmon.log]
disabled = false
index = windows
sourcetype = windows

[monitor:///attack_data/datasets/apt_simulations/ActiveMQ_exploit_Lockbit_Ransomware/windows-security.log]
disabled = false
index = windows
sourcetype = windows

[monitor:///attack_data/datasets/apt_simulations/ActiveMQ_exploit_Lockbit_Ransomware/windows-powershell.log]
disabled = false
index = windows
sourcetype = windows
EOF
```

```bash
docker restart splunk
```
