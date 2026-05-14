# Secure Cloud Platform

A full-stack secure cloud storage platform built for a Master's dissertation. Combines **AES-256-GCM encrypted storage** (MinIO), **immutable blockchain audit trails** (Ethereum Sepolia), **AI anomaly detection** (PyOD ECOD), and **dynamic sandbox analysis** (QEMU + Docker) into a single cohesive system.

---

## Architecture

```
Browser (Next.js 14)
       │
       ▼
  API Gateway (:5000)
  ┌──────┬──────────────┬──────────────┬──────────────┐
  │      │              │              │              │
Storage  Blockchain    AI Detection   Sandbox
(:5001)  (:5002)       (:5003)        (:5004)
MinIO    Sepolia       PyOD ECOD      QEMU / Wine
AES-GCM  Solidity      Redis buffer   Docker-in-Docker
```

---

## Services

| Service | Port | Description |
|---------|------|-------------|
| Frontend (Next.js) | 3000 | React dashboard |
| API Gateway | 5000 | Orchestration layer |
| Storage Service | 5001 | MinIO + AES-256-GCM chunked encryption |
| Blockchain Service | 5002 | Sepolia Web3 + audit log contract |
| AI Detection | 5003 | PyOD ECOD unsupervised detector + Redis buffer |
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

cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
```

Edit `backend/.env`:

```env
PRIVATE_KEY=<your Sepolia wallet private key>
CONTRACT_ADDRESS=          # leave blank until step 3
SEPOLIA_RPC_URL=https://sepolia.infura.io/v3/<your-key>
```

### 2 — Deploy the smart contract

```bash
cd blockchain
npm install
npx hardhat compile
npx hardhat run scripts/deploy.js --network sepolia
```

The script deploys the contract, prints the address, and writes the ABI + address to `backend/abi/SecureDataManagement.json` automatically.

Copy the printed address into `backend/.env` → `CONTRACT_ADDRESS=0x...`

### 3 — Start all services

```bash
# Production
docker-compose up --build

# Development (hot reload)
docker-compose -f docker-compose.dev.yml up --build
```

### 4 — Open the platform

| URL | Description |
|-----|-------------|
| http://localhost:3000 | Main application |
| http://localhost:9001 | MinIO console (minioadmin / minioadmin) |
| http://localhost:5000/health | Gateway health check |

---

## Development Without Docker

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env

# Start each service in a separate terminal
python storage_service.py       # :5001
python blockchain_service.py    # :5002
python ai_detection_service.py  # :5003
python sandbox_service.py       # :5004
python main.py                  # :5000 gateway
```

### Frontend

```bash
cd frontend
npm install
cp .env.example .env
npm run dev                     # http://localhost:3000
```

### Smart Contract

```bash
cd blockchain
npm install
npx hardhat node                                         # local node
npx hardhat run scripts/deploy.js --network localhost    # deploy
npx hardhat test                                         # test suite
```

---

## Project Structure

```
secure-cloud-platform/
├── backend/
│   ├── main.py                     # Gateway entry point (:5000)
│   ├── blockchain_service.py       # Blockchain entry point (:5002)
│   ├── ai_detection_service.py     # AI detection entry point (:5003)
│   ├── sandbox_service.py          # Sandbox entry point (:5004)
│   ├── storage_service.py          # Storage service (:5001)
│   ├── gateway/                    # Gateway sub-package
│   │   ├── config.py               # Service URLs and constants
│   │   ├── clients.py              # AI, storage, blockchain helpers
│   │   └── routes.py               # All 8 API route handlers
│   ├── blockchain/                 # Blockchain sub-package
│   │   ├── web3_client.py          # Web3, nonce lock, receipt semaphore
│   │   └── routes.py               # 9 route handlers
│   ├── ai_detection/               # AI detection sub-package
│   │   ├── config.py               # Thresholds, regex, constants
│   │   ├── redis_buffer.py         # Feature store
│   │   ├── binary_analysis.py      # Static PE/ELF/COM/macOS analysis
│   │   ├── behavioral.py           # Feature extraction
│   │   ├── detector.py             # PyOD ECOD model
│   │   └── routes.py               # /scan, /detect, /stats, /health
│   ├── sandbox/                    # Sandbox sub-package
│   │   ├── config.py               # Docker image names
│   │   ├── platform.py             # ELF arch detection
│   │   ├── trace.py                # strace pattern analysis
│   │   ├── runners.py              # ELF/DOS/Wine execution
│   │   └── routes.py               # /analyze, /health
│   ├── abi/
│   │   └── SecureDataManagement.json   # ABI + deployed address
│   ├── tests/
│   └── requirements.txt
│
├── blockchain/
│   ├── contracts/
│   │   └── SecureDataManagement.sol    # On-chain file registry + audit log
│   ├── scripts/deploy.js               # Deploy + auto-export ABI
│   └── test/
│
├── frontend/
│   ├── app/
│   │   ├── page.tsx                # Dashboard
│   │   ├── upload/                 # File upload + AI scan result
│   │   ├── files/                  # File management (download / share / delete)
│   │   └── audit/                  # Full audit log + charts
│   ├── components/                 # FileCard, AnomalyBadge, Navbar, WalletConnect
│   ├── lib/                        # API client, wagmi config, utils
│   └── types/                      # TypeScript interfaces
│
├── docker-compose.yml
└── docker-compose.dev.yml
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 14, Tailwind CSS, shadcn/ui, Recharts |
| Wallet | RainbowKit + Wagmi v2 |
| Backend | Python 3.10, Flask |
| Blockchain | Solidity 0.8.19, Hardhat, Web3.py |
| Network | Ethereum Sepolia testnet |
| Storage | MinIO (S3-compatible), chunked AES-256-GCM |
| AI/ML | PyOD (ECOD), Scikit-learn |
| Sandbox | Docker-in-Docker, QEMU user-mode, Wine |
| Cache | Redis 7 |
| Container | Docker Compose |

---

## AI Detection

Behavioural anomaly detection using **PyOD ECOD** (Empirical Cumulative Distribution), an unsupervised detector that fits on live traffic buffered in Redis. It refits automatically every 100 events using the last 2000 access records.

**12 behavioural features** — time-of-day, day-of-week, weekend/night flags, hour deviation, file size deviation, recent access frequency (1h / 24h), rapid succession flag, location change, geo-risk score, prior anomaly rate.

**Risk levels:**

| Level | Action |
|-------|--------|
| CRITICAL | Block upload/download |
| HIGH | Block upload/download |
| MEDIUM | Log only |
| NORMAL | Pass |

---

## Sandbox Analysis

Executables (ELF, PE, COM, macOS) are run in an isolated container and their system call trace is analysed for malicious patterns.

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

---

## Security Features

- AES-256-GCM encryption per chunk with PBKDF2 key derivation (600,000 iterations)
- Random salt + nonce prepended to every chunk object
- Immutable audit trail stored on Ethereum Sepolia
- Unsupervised AI anomaly detection on every access event
- Dynamic sandbox execution for all uploaded executables
- On-chain permission access control
- Blockchain audit log writes are fire-and-forget (thread pool, max 5 concurrent) to prevent Infura rate-limit errors under bulk operations

---

*Built as part of a Master's dissertation on decentralised secure cloud storage with AI-driven threat detection.*
