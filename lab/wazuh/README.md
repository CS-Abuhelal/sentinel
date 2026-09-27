# Watching your own PC with Wazuh

This connects Wazuh 4.14 (in Docker) to SENTINEL's live feed. Your Windows PC runs the Wazuh
agent. Wazuh sends every alert of level 3 or higher to SENTINEL, which stores it and shows it at
`http://localhost:5173/?view=pc`. Everything stays on this PC: Wazuh and SENTINEL talk over a
private Docker network, and SENTINEL's ports listen on `127.0.0.1` only.

SENTINEL never changes anything on your PC. It only reads and advises.

## Before you start

- Docker Desktop with the WSL 2 backend.
- About 5 GB of free RAM while Wazuh runs. Close heavy apps.
- Allow the Wazuh indexer's memory mapping, once. Create or edit `%UserProfile%\.wslconfig`:

  ```ini
  [wsl2]
  kernelCommandLine = "sysctl.vm.max_map_count=262144"
  ```

  Then run `wsl --shutdown` and restart Docker Desktop.

## 1. The shared network

```powershell
docker network create sentinel-wazuh
```

## 2. Wazuh in Docker

```powershell
cd $env:USERPROFILE\projects
git ls-remote --tags https://github.com/wazuh/wazuh-docker "v4.14.*"
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.0
cd wazuh-docker\single-node
```

Use the newest `v4.14.x` tag that `ls-remote` lists, in place of `v4.14.0`.

1. Copy `lab\wazuh\docker-compose.override.yml` from the SENTINEL repo into this folder.
2. Create `.env` in this folder containing:

   ```dotenv
   SENTINEL_REPO=C:/path/to/SENTINEL
   ```

3. Open `config\wazuh_cluster\wazuh_manager.conf` and paste the block from
   `lab\wazuh\ossec-integration.xml` just before the last `</ossec_config>`. Replace
   `REPLACE_WITH_SENTINEL_INGEST_TOKEN` with `SENTINEL_INGEST_TOKEN` from SENTINEL's `.env`.
4. Generate the certificates and start Wazuh:

   ```powershell
   docker compose -f generate-indexer-certs.yml run --rm generator
   docker compose up -d
   ```

The Wazuh dashboard is at `https://localhost`, with user `admin` and password `SecretPassword`.
These are the wazuh-docker defaults, and they're only reachable from this PC.

## 3. SENTINEL

In SENTINEL's `.env` (copied from `.env.example`), set `WAZUH_INDEXER_PASSWORD=SecretPassword`.
Check that `WAZUH_CERTS_DIR` points to `wazuh-docker\single-node\config\wazuh_indexer_ssl_certs`.
Then, from the SENTINEL repo:

```powershell
docker compose -f docker-compose.yml -f docker-compose.wazuh.yml up -d --build
```

## 4. The agent on this PC

In an **administrator** PowerShell, using the same version as the Wazuh tag:

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.0-1.msi -OutFile $env:TEMP\wazuh-agent.msi
msiexec.exe /i $env:TEMP\wazuh-agent.msi /q WAZUH_MANAGER="127.0.0.1" WAZUH_AGENT_NAME="my-pc"
NET START Wazuh
```

The agent is named `my-pc`, so your real computer name never shows up in SENTINEL's data.

## 5. Check it works

Trigger five harmless failed logons with a user that doesn't exist, so no real account gets
locked. Type any password when asked:

```powershell
1..5 | ForEach-Object { runas /user:$env:COMPUTERNAME\sentinel-test-nobody cmd }
```

Within about 10 seconds, `http://localhost:5173/?view=pc` shows `wazuh-60122` "Logon failure"
alerts.

## Stopping and starting

- **Stop Wazuh:** `docker compose down` in `wazuh-docker\single-node`. Your data is kept in
  Docker volumes.
- **Stop SENTINEL:** `docker compose -f docker-compose.yml -f docker-compose.wazuh.yml down`.
- **Missed alerts:** alerts that Wazuh raised while SENTINEL was stopped are fetched from the
  Wazuh indexer the next time SENTINEL starts.

## Troubleshooting

- **No alerts arrive.** Run
  `docker compose exec wazuh.manager grep -i integrat /var/ossec/logs/ossec.log`.
  If the integration isn't executable, copy both files in and fix their permissions:

  ```powershell
  docker compose cp ..\..\SENTINEL\lab\wazuh\integrations\. wazuh.manager:/var/ossec/integrations/
  docker compose exec wazuh.manager chmod 750 /var/ossec/integrations/custom-sentinel /var/ossec/integrations/custom-sentinel.py
  docker compose exec wazuh.manager chown root:wazuh /var/ossec/integrations/custom-sentinel /var/ossec/integrations/custom-sentinel.py
  docker compose restart wazuh.manager
  ```

- **The page says the backfill failed.** Read the detail line. A TLS error means
  `WAZUH_CERTS_DIR` is wrong. A 401 means the indexer password in `.env` is wrong.
