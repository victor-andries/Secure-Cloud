import axios, { AxiosInstance } from "axios";
import type {
  UploadResponse,
  DownloadResponse,
  HealthResponse,
  AuditLogsResponse,
  Permission
} from "@/types";

const BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:5000";

const apiClient: AxiosInstance = axios.create({
  baseURL: BASE_URL,
  timeout: 120_000,
  headers: {
    Accept: "application/json"
  }
});

// ─── Interceptors ─────────────────────────────────────────────────────────────

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const message: string =
      error.response?.data?.error ??
      error.response?.data?.message ??
      error.message ??
      "Unknown error";
    console.error(`[API Error] ${error.config?.url ?? ""}: ${message}`);
    return Promise.reject(new Error(message));
  }
);

// ─── File Operations ──────────────────────────────────────────────────────────

/**
 * Upload a file with AES-256-GCM encryption via the gateway.
 */
export async function uploadFile(formData: FormData): Promise<UploadResponse> {
  const response = await apiClient.post("/files/upload", formData, {
    headers: { "Content-Type": "multipart/form-data" },
    timeout: 300_000
  });
  const d = response.data;
  return {
    success: d.success,
    fileId: d.file_id ?? d.fileId,
    fileName: d.file_name ?? d.fileName,
    fileSize: d.file_size ?? d.fileSize,
    fileHash: d.file_hash ?? d.fileHash,
    numChunks: d.num_chunks ?? d.numChunks,
    txHash: d.tx_hash ?? d.txHash ?? null,
    aiScore: d.ai_score ?? d.aiScore ?? 0,
    aiLevel: d.ai_level ?? d.aiLevel ?? "NORMAL"
  };
}

/**
 * Download and decrypt a file by ID.
 */
export async function downloadFile(
  fileId: string,
  password: string,
  userAddress: string
): Promise<DownloadResponse> {
  const response = await apiClient.post(`/files/download/${fileId}`, {
    password,
    user_address: userAddress
  });
  const d = response.data;
  return {
    success: d.success,
    fileId: d.file_id ?? d.fileId,
    data: d.data,
    size: d.size,
    aiScore: d.ai_score ?? d.aiScore ?? 0,
    aiLevel: d.ai_level ?? d.aiLevel ?? "NORMAL"
  };
}

/**
 * Delete a file and all its chunks from storage.
 */
export async function deleteFile(
  fileId: string,
  userAddress: string
): Promise<{ success: boolean }> {
  const response = await apiClient.delete(`/files/${fileId}`, {
    data: { user_address: userAddress }
  });
  return response.data as { success: boolean };
}

// ─── Access Control ───────────────────────────────────────────────────────────

/**
 * Grant access permission on a file to another user.
 */
export async function grantAccess(
  fileId: string,
  userAddress: string,
  permission: Permission
): Promise<{ success: boolean; txHash?: string }> {
  const response = await apiClient.post(`/files/${fileId}/access/grant`, {
    user_address: userAddress,
    permission
  });
  return response.data as { success: boolean; txHash?: string };
}

/**
 * Revoke access from a user for a file.
 */
export async function revokeAccess(
  fileId: string,
  userAddress: string
): Promise<{ success: boolean; txHash?: string }> {
  const response = await apiClient.post(`/files/${fileId}/access/revoke`, {
    user_address: userAddress
  });
  return response.data as { success: boolean; txHash?: string };
}

// ─── Audit / Monitoring ───────────────────────────────────────────────────────

/**
 * Get paginated access logs for a specific file.
 */
export async function getAuditLogs(
  fileId: string,
  page = 0,
  pageSize = 20
): Promise<AuditLogsResponse> {
  const response = await apiClient.get(`/audit/${fileId}`, {
    params: { page, page_size: pageSize }
  });
  const d = response.data;
  const raw: Record<string, unknown>[] = d.logs ?? d.anomalies ?? [];
  return {
    page: d.page ?? page,
    pageSize: d.page_size ?? pageSize,
    logs: raw.map(mapLog)
  };
}

/**
 * Get all anomaly-flagged access logs (paginated).
 */
function mapLog(l: Record<string, unknown>) {
  return {
    user:        (l.user ?? l.address ?? "") as string,
    fileId:      (l.file_id ?? l.fileId ?? "") as string,
    action:      (l.action ?? "") as string,
    ipAddress:   (l.ip_address ?? l.ipAddress ?? "") as string,
    timestamp:   (l.timestamp ?? 0) as number,
    success:     (l.success ?? true) as boolean,
    anomalyFlag:  (l.anomaly_flag ?? l.anomalyFlag ?? false) as boolean,
    anomalyLevel: (l.anomaly_level ?? l.anomalyLevel ?? undefined) as import("@/types").AnomalyLevel | undefined,
  };
}

export async function getAllAuditLogs(page = 0, pageSize = 50): Promise<AuditLogsResponse> {
  const response = await apiClient.get("/audit/all", {
    params: { page, page_size: pageSize }
  });
  const d = response.data;
  const raw: Record<string, unknown>[] = d.logs ?? d.anomalies ?? [];
  return {
    page: d.page ?? page,
    pageSize: d.page_size ?? pageSize,
    logs: raw.map(mapLog)
  };
}

export async function getAnomalyLogs(page = 0, pageSize = 50): Promise<AuditLogsResponse> {
  const response = await apiClient.get("/audit/anomalies", {
    params: { page, page_size: pageSize }
  });
  const d = response.data;
  const raw: Record<string, unknown>[] = d.anomalies ?? d.logs ?? [];
  return {
    page: d.page ?? page,
    pageSize: d.page_size ?? pageSize,
    anomalies: raw.map(mapLog)
  };
}

// ─── Health ───────────────────────────────────────────────────────────────────

/**
 * Fetch health status for all services.
 */
export async function getHealth(): Promise<HealthResponse> {
  const response = await apiClient.get<HealthResponse>("/health");
  return response.data;
}

export default apiClient;
