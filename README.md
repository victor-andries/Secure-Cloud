# Secure Cloud Platform

A full-stack secure cloud storage platform built for a Master's dissertation. Combines **AES-256-GCM encrypted storage** (MinIO), **immutable blockchain audit trails** (Ethereum Sepolia + Arbitrum Sepolia), **three-layer AI threat detection** (static analysis, YARA signatures, PyOD ECOD), and **dynamic sandbox analysis** (QEMU + Docker) into a single cohesive system.

---

## Architecture

```
  Browser (MetaMask)
          │
          ▼
    Frontend (Next.js)
          │
          ▼
     API Gateway  ──────── wallet auth · EIP-191 signed nonces (Redis)
          │
          ├── Storage Service  ──────── MinIO · AES-256-GCM chunked encryption
          │
          ├── Blockchain Service  ───── Eth Sepolia + Arbitrum Sepolia
          │
          ├── AI Detection  ─────────── Static analysis · YARA · PyOD ECOD
          │                             (12-feature behavioural buffer in Redis)
          │
          └── Sandbox Service  ──────── QEMU user-mode · Wine · DOSBox
```

The active blockchain network is determined by the user's MetaMask wallet. Switching networks in MetaMask instantly routes all blockchain calls to the corresponding deployed contract — no configuration changes needed.

---

## Services

| Service | Port | Description |
|---------|------|-------------|
| Frontend (Next.js) | 3000 | React dashboard with RainbowKit wallet connect |
| API Gateway | 5000 | Orchestration and auth layer |
| Storage Service | 5001 | MinIO + AES-256-GCM chunked encryption |
| Blockchain Service | 5002 | Multi-chain Web3 + audit log contract |
| AI Detection | 5003 | Static analysis + YARA + PyOD ECOD behavioral detector |
| Sandbox Service | 5004 | Dynamic analysis (ELF/PE/DOS/macOS via QEMU + Wine) |
| MinIO S3 API | 9000 | Object storage |
| MinIO Console | 9001 | Web UI |
| Redis | 6379 | Behavioural feature buffer |

---

## Quick Start (Docker)

### 1 — Clone and configure

```bash
git clone <repo-url> secure-cloud-platform
cd secure-cloud-platform
cp .env.example .env
```

Fill in `.env` with your values (see `.env.example` for all variables). At minimum you need:

```env
# Wallet
PRIVATE_KEY=<your testnet wallet private key>

# Infura (or any RPC provider)
SEPOLIA_RPC_URL=https://sepolia.infura.io/v3/<your-key>
ARBITRUM_SEPOLIA_RPC_URL=https://arbitrum-sepolia.infura.io/v3/<your-key>

# Filled in after step 2
SEPOLIA_CONTRACT_ADDRESS=
ARBITRUM_SEPOLIA_CONTRACT_ADDRESS=

# WalletConnect (free at cloud.walletconnect.com)
NEXT_PUBLIC_WALLETCONNECT_PROJECT_ID=<your-project-id>
NEXT_PUBLIC_API_URL=
```

### 2 — Deploy the smart contract

The same contract can be deployed to one or both networks. Each deployment produces an independent on-chain state.

```bash
cd blockchain
npm install
npx hardhat compile

# Deploy to Sepolia
npx hardhat run scripts/deploy.js --network sepolia

# Deploy to Arbitrum Sepolia (optional — for multi-chain comparison)
npx hardhat run scripts/deploy.js --network arbitrumSepolia
```

Each deployment prints the contract address and writes the ABI to `backend/abi/`. Copy the addresses into `.env`:

```env
SEPOLIA_CONTRACT_ADDRESS=0x...
ARBITRUM_SEPOLIA_CONTRACT_ADDRESS=0x...
```

### 3 — Build sandbox images (first time only)

```bash
docker compose --profile build up sandbox-dos-builder sandbox-wine-builder
```

### 4 — Start all services

```bash
# Production
docker compose up --build

# Development (hot reload)
docker compose -f docker-compose.dev.yml up --build
```

### 5 — Open the platform

| URL | Description |
|-----|-------------|
| http://localhost:3000 | Main application |
| http://localhost:9001 | MinIO console |
| http://localhost:5000/health | Gateway health check |

Connect MetaMask to Sepolia or Arbitrum Sepolia — the platform follows the active network automatically.

---

## Development Without Docker

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Start each service in a separate terminal
python storage_service.py
python blockchain_service.py
python ai_detection_service.py
python sandbox_service.py
python main.py
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

### Smart Contract

```bash
cd blockchain
npm install
npx hardhat node                                          # local node
npx hardhat run scripts/deploy.js --network localhost     # deploy locally
npx hardhat test                                          # test suite
```

---

## Project Structure

```
secure-cloud-platform/
├── .env.example                        # All environment variables with defaults
├── docker-compose.yml                  # Production stack
├── docker-compose.dev.yml              # Development stack (hot reload)
│
├── backend/
│   ├── main.py                         # Gateway entry point (:5000)
│   ├── blockchain_service.py           # Blockchain entry point (:5002)
│   ├── ai_detection_service.py         # AI detection entry point (:5003)
│   ├── sandbox_service.py              # Sandbox entry point (:5004)
│   ├── storage_service.py              # Storage service (:5001)
│   ├── gateway/
│   │   ├── config.py                   # Service URLs and constants
│   │   ├── clients.py                  # AI, storage, blockchain helpers
│   │   ├── routes.py                   # Flask app + CORS registration
│   │   ├── routes_files.py             # Upload / download / delete
│   │   ├── routes_access.py            # Grant / revoke access
│   │   ├── routes_audit.py             # Audit log proxy
│   │   ├── routes_auth.py              # Wallet nonce + session auth
│   │   └── routes_health.py            # Health aggregator
│   ├── blockchain/
│   │   ├── web3_client.py              # Multi-chain Web3, nonce lock, receipt pool
│   │   └── routes.py                   # Register, access, audit, health endpoints
│   ├── ai_detection/
│   │   ├── binary_analysis.py          # Layer 1: static PE/ELF/COM/macOS analysis
│   │   ├── yara_scanner.py             # Layer 2: YARA signature matching
│   │   ├── detector.py                 # Layer 3: PyOD ECOD behavioral model
│   │   ├── redis_buffer.py             # Feature store
│   │   └── routes.py                   # /scan, /detect, /stats, /health
│   ├── sandbox/
│   │   ├── platform.py                 # ELF arch detection
│   │   ├── trace.py                    # strace pattern analysis
│   │   ├── runners.py                  # ELF/DOS/Wine execution
│   │   └── routes.py                   # /analyze, /health
│   ├── abi/
│   │   ├── SecureDataManagement.json               # Default ABI
│   │   └── SecureDataManagement-arbitrumSepolia.json
│   ├── rules/
│   │   ├── god-mode-rules/             # Custom YARA rules
│   │   └── signature-base/yara/        # Community YARA signature library
│   └── requirements.txt
│
├── blockchain/
│   ├── contracts/
│   │   └── SecureDataManagement.sol    # On-chain file registry + audit log
│   ├── scripts/deploy.js               # Deploy + auto-export ABI per network
│   └── test/
│
└── frontend/
    ├── app/
    │   ├── page.tsx                    # Dashboard (per-chain stats)
    │   ├── providers.tsx               # Wagmi + RainbowKit + ChainSync
    │   ├── upload/                     # File upload + AI scan result
    │   ├── files/                      # File management (download / share / delete)
    │   └── audit/                      # Audit log + charts
    ├── components/
    ├── lib/
    │   ├── api.ts                      # Axios client (injects X-Chain-ID on every request)
    │   └── wagmi.ts                    # Wagmi config (Sepolia + Arbitrum Sepolia)
    └── types/
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 14, Tailwind CSS, shadcn/ui, Recharts |
| Wallet | RainbowKit + Wagmi v2 |
| Backend | Python 3.10, Flask |
| Blockchain | Solidity 0.8.19, Hardhat, Web3.py 6 |
| Networks | Ethereum Sepolia + Arbitrum Sepolia (switchable via MetaMask) |
| Storage | MinIO (S3-compatible), chunked AES-256-GCM |
| AI/ML | PyOD (ECOD), YARA, static binary analysis |
| Sandbox | Docker-in-Docker, QEMU user-mode, Wine |
| Cache | Redis 7 |
| Container | Docker Compose |

---

## AI Detection Pipeline

Every uploaded file passes through three layers before reaching storage.

### Layer 1 — Static Binary Analysis
Structural inspection without execution. Detects:
- PE imports (suspicious WinAPI calls, packed headers)
- ELF anomalies (RWXP segments, RPATH hijacking)
- Mach-O (dangerous strings, @rpath manipulation)
- Archive zip-bomb protection (50 MB total / 2 MB per member)
- Script patterns (19 high-risk, 27 medium-risk keyword categories)

### Layer 2 — YARA Signature Matching
Compiled at startup from two rulesets:
- **God-mode rules** — custom rules for platform-specific threats
- **Signature-base** — community YARA library (malware families, ATM malware, ransomware, RATs)

### Layer 3 — Behavioral Anomaly Detection
**PyOD ECOD** (Empirical Cumulative Distribution), an unsupervised detector that fits on live traffic buffered in Redis. Refits automatically every 100 events using the last 2000 access records.

**12 behavioral features** — time-of-day, day-of-week, weekend/night flags, hour deviation, file size deviation, recent access frequency (1h / 24h), rapid succession flag, location change, geo-risk score, prior anomaly rate.

### Risk Levels

| Level | Action |
|-------|--------|
| CRITICAL | Block upload/download |
| HIGH | Block upload/download |
| MEDIUM | Log only |
| NORMAL | Pass |

---

## Sandbox Analysis

Executables are run in an isolated container and their system call trace is analysed for malicious patterns.

| Format | Runner |
|--------|--------|
| Native ELF (x86-64) | Docker seccomp sandbox |
| ARM / MIPS / RISC-V ELF | QEMU user-mode emulation |
| DOS COM / EXE | DOSBox container |
| Windows PE | Wine container |

Files that are **MALICIOUS** or **SUSPICIOUS** are blocked before reaching storage.

---

## Smart Contract

`SecureDataManagement.sol` provides:

- **`registerFile`** — store file metadata and chunk locations on-chain
- **`grantAccess` / `revokeAccess`** — permission management (NONE / READ / WRITE / FULL)
- **`logAccess`** — immutable audit event (every upload, download, delete)
- **`getAllAccessLogs`** — paginated full audit trail
- **`getAnomalyLogs`** — anomaly-only subset
- **`getAccessLogs(fileId)`** — per-file history

The same contract is deployed independently on each supported network. Switching MetaMask to a different network routes all calls to that network's contract — file registrations and audit logs are per-network.

---

## Security Features

- AES-256-GCM encryption per chunk with PBKDF2 key derivation (600,000 iterations)
- Random salt + nonce prepended to every chunk object
- Immutable audit trail on Ethereum Sepolia and Arbitrum Sepolia
- Three-layer AI threat detection on every upload (static + YARA + behavioral)
- Dynamic sandbox execution for all uploaded executables
- On-chain permission access control (READ / WRITE / FULL)
- Wallet-based authentication via EIP-191 signed nonces (session tokens stored in Redis)
- Blockchain audit log writes are fire-and-forget (thread pool, max 5 concurrent) to prevent rate-limit errors under bulk operations

---

---

## Credits

**YARA Rules — Florian Roth (Neo23x0)**
Both YARA rulesets bundled in `backend/rules/` are authored by Florian Roth and used under the [CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/) licence (non-commercial use only):
- [signature-base](https://github.com/Neo23x0/signature-base) — community malware signature library
- [God Mode Rule](https://github.com/Neo23x0/god-mode-rules) — broad-spectrum threat detection rule (v0.8.1)

**PyOD / ECOD**
The Layer 3 behavioural anomaly detector uses the ECOD algorithm from the PyOD library:
> Li, Z., Zhao, Y., Botta, N., Ionescu, C., & Hu, X. (2022). *ECOD: Unsupervised Outlier Detection Using Empirical Cumulative Distribution Functions.* IEEE Transactions on Knowledge and Data Engineering. https://doi.org/10.1109/TKDE.2022.3160206

---

*Built as part of a Master's dissertation on decentralised secure cloud storage with AI-driven threat detection for ASE DICE department, IT&C Security Master.*