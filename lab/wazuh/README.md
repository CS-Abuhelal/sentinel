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

## 0. SENTINEL's settings

From the SENTINEL repo, copy `.env.example` to `.env` and generate the ingest token:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Put the result in `SENTINEL_INGEST_TOKEN` in `.env`. The same token goes into Wazuh's
configuration in step 2.

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
These are the wazuh-docker defaults. `docker-compose.override.yml` publishes only the dashboard
(`127.0.0.1:443`) and the agent ports (`127.0.0.1:1514`, `127.0.0.1:1515`), all on `127.0.0.1`.
The indexer (9200) and the API (55000) are not published at all; SENTINEL reaches them over the
`sentinel-wazuh` network. Change the default passwords before connecting your PC: follow the
wazuh-docker README's instructions for changing Wazuh users' passwords, then update
`WAZUH_INDEXER_PASSWORD` in SENTINEL's `.env` to match.

## 3. SENTINEL

In SENTINEL's `.env` (copied from `.env.example`), set `WAZUH_INDEXER_PASSWORD` to the indexer
`admin` password you set in step 2.
Check that `WAZUH_CERTS_DIR` points to `wazuh-docker\single-node\config\wazuh_indexer_ssl_certs`.
Then, from the SENTINEL repo:

```powershell
docker compose -f docker-compose.yml -f docker-compose.wazuh.yml up -d --build
```

## 4. The agent on this PC

In an **administrator** PowerShell. Set `$version` to the tag you cloned in step 2, without the
leading `v` (for `v4.14.2`, use `4.14.2`):

```powershell
$version = "4.14.0"
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-$version-1.msi" -OutFile $env:TEMP\wazuh-agent.msi
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

## 6. AI investigations (phase 2)

SENTINEL groups the alerts into incidents, and a local model investigates every incident of level
7 or higher with read-only tools. It writes advice and never acts on the PC.

1. Start Ollama with `qwen3:14b` (drop `--gpus all` if you have no NVIDIA GPU). If the container
   already exists, `docker start ollama` is enough.

   ```powershell
   docker run -d --gpus all -p 11434:11434 -v ollama:/root/.ollama --name ollama ollama/ollama:0.34.4
   docker exec ollama ollama pull qwen3:14b
   ```

2. Run the worker in one place only. Step 3 already starts it as the `worker` compose service. To
   run it on the host instead, stop the service first:

   ```powershell
   docker compose -f docker-compose.yml -f docker-compose.wazuh.yml stop worker
   $env:DATABASE_URL = "postgresql+psycopg://sentinel:sentinel_dev@127.0.0.1:5432/sentinel"
   python -m pipeline.worker
   ```

   Never run both. The worker holds a database lock, so a second one logs "Another worker is
   already running." and exits.

3. `OLLAMA_URL` tells the worker and the live page's model status where Ollama is. In Docker it
   defaults to `http://host.docker.internal:11434`, and on the host to `http://localhost:11434`.
   Set it in `.env` only if Ollama runs somewhere else. The status bar shows the model as online
   only when `qwen3:14b` is pulled.

4. Trigger a burst of failed logons with the same fake user, so Wazuh raises "Multiple Windows
   Logon Failures" (60204, level 10):

   ```powershell
   $c = [pscredential]::new("$env:COMPUTERNAME\sentinel-test-nobody", (ConvertTo-SecureString "wrong" -AsPlainText -Force)); 1..12 | ForEach-Object { try { Start-Process cmd -Credential $c -ErrorAction Stop } catch {} }
   ```

   Within a minute the **Incidents** tab shows a queued incident. After the model finishes (a
   few minutes on `qwen3:14b`), it opens with the evidence, the verdict and the advice. A failed
   investigation can be retried from the same page.

## Stopping and starting

- **Stop Wazuh:** `docker compose down` in `wazuh-docker\single-node`. Your data is kept in
  Docker volumes.
- **Stop SENTINEL:** `docker compose -f docker-compose.yml -f docker-compose.wazuh.yml down`.
- **Missed alerts:** alerts that Wazuh raised while SENTINEL was stopped are fetched from the
  Wazuh indexer the next time SENTINEL starts.

## Troubleshooting

- **No alerts arrive.** Run
  `docker compose exec wazuh.manager grep -i integrat /var/ossec/logs/ossec.log`.
  If it says the integration can't be run (a Windows bind mount can lose the executable bit),
  copy the files in instead of mounting them:
  1. In `docker-compose.override.yml`, delete the `volumes:` block under `wazuh.manager` (the two
     `custom-sentinel` lines), then run `docker compose up -d` to recreate the manager.
  2. Copy the files in and fix their permissions:

     ```powershell
     docker compose cp $env:USERPROFILE\projects\SENTINEL\lab\wazuh\integrations\. wazuh.manager:/var/ossec/integrations/
     docker compose exec wazuh.manager chmod 750 /var/ossec/integrations/custom-sentinel /var/ossec/integrations/custom-sentinel.py
     docker compose exec wazuh.manager chown root:wazuh /var/ossec/integrations/custom-sentinel /var/ossec/integrations/custom-sentinel.py
     docker compose restart wazuh.manager
     ```

  Repeat step 2 whenever the integration script changes.

- **The page says the backfill failed.** Read the detail line. A TLS error means
  `WAZUH_CERTS_DIR` is wrong. A 401 means the indexer password in `.env` is wrong. If it says
  "Retrying in 30 seconds", the indexer is still starting; SENTINEL keeps trying on its own.

- **Wazuh shows as offline after Docker Desktop restarts, and no new alerts arrive.** The manager
  container can start without its services when old process files are left over. Check and start
  them:

  ```powershell
  docker compose exec wazuh.manager /var/ossec/bin/wazuh-control status
  docker compose exec wazuh.manager /var/ossec/bin/wazuh-control start
  ```

  The first command reports "not running" for each service and removes the old process files.
  The second starts them. Within a minute the agent reconnects and sends the alerts it queued.
