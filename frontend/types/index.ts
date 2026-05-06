// ─── Blockchain / File Types ──────────────────────────────────────────────────

export interface ChunkInfo {
  chunkId: string;
  chunkHash: string;
  chunkSize: number;
  chunkLocation: string;
}

export interface FileRecord {
  fileId: string;
  fileHash: string;
  fileName: string;
  fileSize: number;
  owner: string;
  timestamp: number;
  isActive: boolean;
  chunks?: ChunkInfo[];
  txHash?: string;
  aiScore?: number;
  aiLevel?: AnomalyLevel;
  numChunks?: number;
}

// ─── Access Control ───────────────────────────────────────────────────────────

export type Permission = "NONE" | "READ" | "WRITE" | "FULL";

export interface AccessLog {
  user: string;
  fileId: string;
  action: string;
  ipAddress: string;
  timestamp: number;
  success: boolean;
  anomalyFlag: boolean;
  anomalyLevel?: AnomalyLevel;
}

// ─── AI Detection ─────────────────────────────────────────────────────────────

export type AnomalyLevel = "NORMAL" | "MEDIUM" | "HIGH" | "CRITICAL";

export interface ModelScores {
  autoencoder: number;
  isolation_forest: number;
  bilstm: number;
  random_forest: number;
}

export interface AnomalyFeatures {
  hour_norm: number;
  dow_norm: number;
  is_weekend: boolean;
  is_night: boolean;
  hour_deviation: number;
  size_deviation: number;
  recent_1h: number;
  recent_24h: number;
  freq_score: number;
  rapid_succession: boolean;
  location_change: number;
  geo_risk: number;
  prev_anomaly_norm: number;
}

export interface AnomalyDetection {
  userId: string;
  ensembleScore: number;
  level: AnomalyLevel;
  recommendedAction: "BLOCK" | "ALERT" | "LOG" | "PASS";
  isAnomalous: boolean;
  modelScores: ModelScores;
  features: AnomalyFeatures;
}

// ─── API Responses ────────────────────────────────────────────────────────────

export interface UploadResponse {
  success: boolean;
  fileId: string;
  fileName: string;
  fileSize: number;
  fileHash: string;
  numChunks: number;
  txHash: string | null;
  aiScore: number;
  aiLevel: AnomalyLevel;
}

export interface DownloadResponse {
  success: boolean;
  fileId: string;
  data: string; // base64 encoded
  size: number;
  aiScore: number;
  aiLevel: AnomalyLevel;
}

export interface ServiceStatus {
  status: "ok" | "error" | "degraded";
  detail?: Record<string, unknown>;
  error?: string;
}

export interface HealthResponse {
  status: "ok" | "degraded" | "error";
  service: string;
  services?: {
    storage: ServiceStatus;
    blockchain: ServiceStatus;
    ai_detection: ServiceStatus;
  };
}

export interface AuditLogsResponse {
  fileId?: string;
  page: number;
  pageSize: number;
  logs?: AccessLog[];
  anomalies?: AccessLog[];
}

export interface UserStats {
  userId: string;
  totalEvents: number;
  totalAnomalies: number;
  levelDistribution: Record<AnomalyLevel, number>;
  averageScore: number;
  maxScore: number;
}

// ─── Component Props ──────────────────────────────────────────────────────────

export interface StatCardProps {
  title: string;
  value: string | number;
  icon: React.ReactNode;
  trend?: {
    value: number;
    label: string;
    positive: boolean;
  };
  color?: "primary" | "secondary" | "danger" | "warning" | "success";
}

export interface FileCardProps {
  file: FileRecord;
  onDownload: (fileId: string) => void;
  onShare: (fileId: string) => void;
  onDelete: (fileId: string) => void;
  deleting?: boolean;
}

export interface AnomalyBadgeProps {
  level: AnomalyLevel;
  score?: number;
}
