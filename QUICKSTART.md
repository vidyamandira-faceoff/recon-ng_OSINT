# Recon-ng Quickstart Guide (Windows)

This repository is fully configured and ready for reconnaissance operations via interactive terminal, CLI scripting, or the modern Web UI dashboard.

---

## 1. Starting Recon-ng

Use the provided batch scripts in PowerShell or Command Prompt:

### Web Dashboard & REST API (Recommended)
```powershell
.\recon-web.bat
```
- **Web UI:** [http://127.0.0.1:5000](http://127.0.0.1:5000)
- **Interactive Swagger REST API:** [http://127.0.0.1:5000/api/](http://127.0.0.1:5000/api/)

### Interactive Console
```powershell
.\recon-ng.bat
```

### Scripting / Non-Interactive CLI
```powershell
.\recon-cli.bat -M
```

---

## 2. Using the Web Dashboard

The web dashboard is a minimal, single-page application that gives you full GUI control over Recon-ng:

1. **Workspace Control (Top Bar)**:
   - Switch active workspaces instantly.
   - Click **`+ New`** to create and activate a new project workspace.
   - Click **`🗑️`** to delete the selected workspace.
2. **Dashboard Tab**:
   - Live metric cards for `domains`, `hosts`, `contacts`, `vulnerabilities`.
   - Table of all database records and module run activity counts.
3. **Data & Tables Tab**:
   - Browse tables (`domains`, `hosts`, `companies`, `credentials`, `ports`, `vulnerabilities`, etc.).
   - Instant search filter for harvested records.
   - Click **`+ Add Record`** to insert new targets (domains, hosts, contacts, etc.).
   - Delete individual rows or clear entire tables.
   - One-click export to CSV or JSON.
4. **Modules & Run Tab**:
   - Filter and search all 80+ loaded modules.
   - Inspect module options and descriptions.
   - Edit parameters and click **`🚀 Run Module`**.
   - Output streams into the embedded live terminal window.
5. **API Keys Tab**:
   - View, add, update, and delete third-party API credentials (`shodan_api`, `censysio_id`, `virustotal_api`, `github_api`, `bing_api`).
6. **Global Options Tab**:
   - Configure global settings (`NAMESERVER`, `PROXY`, `THREADS`, `TIMEOUT`, `USER-AGENT`, `VERBOSITY`).
7. **Reports & Exports Tab**:
   - Access interactive HTML reports and download tables in CSV, JSON, XLSX, or XML.

---

## 3. Terminal & CLI Workflow

### Step 1: Create or Select a Workspace
```text
[recon-ng][default] > workspaces create target_project
[recon-ng][target_project] >
```

### Step 2: Add Target Information
```text
[recon-ng][target_project] > db insert domains
domain (TEXT): example.com
notes (TEXT): Primary target domain
```
View database records anytime:
```text
[recon-ng][target_project] > show domains
```

### Step 3: Search and Load a Module
```text
[recon-ng][target_project] > modules search domains-hosts
[recon-ng][target_project] > modules load recon/domains-hosts/certificate_transparency
```

### Step 4: Inspect Options and Run
```text
[recon-ng][target_project][certificate_transparency] > options list
[recon-ng][target_project][certificate_transparency] > run
[recon-ng][target_project][certificate_transparency] > show hosts
```

### Step 5: Generate Reports
```text
[recon-ng][target_project] > modules load reporting/html
[recon-ng][target_project][html] > options set CREATOR YourName
[recon-ng][target_project][html] > options set CUSTOMER TargetCompany
[recon-ng][target_project][html] > run
```

---

## 4. Managing API Keys

- **List existing keys:**
  ```text
  [recon-ng][default] > keys list
  ```
- **Add an API key:**
  ```text
  [recon-ng][default] > keys add <key_name> <value>
  ```
- **Remove an API key:**
  ```text
  [recon-ng][default] > keys remove <key_name>
  ```

---

## 5. REST API Endpoints Overview

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/workspaces/` | List all workspaces |
| `POST` | `/api/workspaces/` | Create a new workspace (`{"name": "project"}`) |
| `DELETE` | `/api/workspaces/<name>` | Delete a workspace |
| `PATCH` | `/api/workspaces/<name>` | Activate a workspace (`{"status": "active"}`) |
| `GET` | `/api/tables/` | List all tables in active workspace |
| `GET` | `/api/tables/<table>` | Get records (supports `?format=csv` or `json`) |
| `POST` | `/api/tables/<table>` | Insert record (`{"domain": "target.com"}`) |
| `DELETE` | `/api/tables/<table>` | Delete record (`?rowid=1`) or clear table |
| `GET` | `/api/modules/` | List all loaded modules |
| `GET` | `/api/modules/<path>` | Module metadata and options |
| `POST` | `/api/modules/<path>/run` | Execute module and return terminal output |
| `GET` | `/api/keys/` | List all third-party API keys |
| `POST` | `/api/keys/` | Add/update API key (`{"name": "shodan_api", "value": "..."}`) |
| `DELETE` | `/api/keys/<name>` | Delete an API key |
| `GET` | `/api/options/` | Get global framework options |
| `PATCH` | `/api/options/` | Update global options |
| `GET` | `/api/dashboard` | Harvested records count & module history |
| `GET` | `/api/reports/` | List interactive reports |
| `GET` | `/api/exports` | List supported export formats |
