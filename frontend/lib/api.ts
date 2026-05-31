import axios, { AxiosInstance } from "axios";
import { getOrCreateSession, clearSession } from "./session";
import type {
  UploadResponse,
  DownloadResponse,
  HealthResponse,
  AuditLogsResponse,
  Permission
} from "@/types";

const BASE_URL = process.env.NEXT_PUBLIC_API_URL;

const apiClient: AxiosInstance = axios.create({
  baseURL: BASE_URL,
  timeout: 120_000,
  headers: {
    Accept: "application/json"
  }
});

let _chainId = "11155111";

export function setApiChainId(id: string | number): void {
  _chainId = String(id);
}

apiClient.interceptors.request.use((config) => {
  config.headers["X-Chain-ID"] = _chainId;
  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      clearSession();
    }
    const message: string =
      error.response?.data?.error ??
      error.response?.data?.message ??
      error.message ??
      "Unknown error";
    console.error(`[API Error] ${error.config?.url ?? ""}: ${message}`);
    return Promise.reject(new Error(message));
  }
);

export async function uploadFile(formData: FormData, address: string): Promise<UploadResponse> {
  const token = await getOrCreateSession(address);
  const response = await apiClient.post("/files/upload", formData, {
    headers: { "Content-Type": "multipart/form-data", "X-Session-Token": token },
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

export async function downloadFile(
  fileId: string,
  password: string,
  userAddress: string
): Promise<DownloadResponse> {
  const token = await getOrCreateSession(userAddress);
  const response = await apiClient.post(`/files/download/${fileId}`, { password }, {
    headers: { "X-Session-Token": token },
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

export async function deleteFile(
  fileId: string,
  userAddress: string
): Promise<{ success: boolean }> {
  const token = await getOrCreateSession(userAddress);
  const response = await apiClient.delete(`/files/${fileId}`, {
    headers: { "X-Session-Token": token },
  });
  return response.data as { success: boolean };
}

export async function grantAccess(
  fileId: string,
  ownerAddress: string,
  granteeAddress: string,
  permission: Permission
): Promise<{ success: boolean; txHash?: string }> {
  const token = await getOrCreateSession(ownerAddress);
  const response = await apiClient.post(
    `/files/${fileId}/access/grant`,
    { user_address: granteeAddress, permission },
    { headers: { "X-Session-Token": token } }
  );
  return response.data as { success: boolean; txHash?: string };
}

export async function revokeAccess(
  fileId: string,
  ownerAddress: string,
  granteeAddress: string
): Promise<{ success: boolean; txHash?: string }> {
  const token = await getOrCreateSession(ownerAddress);
  const response = await apiClient.post(
    `/files/${fileId}/access/revoke`,
    { user_address: granteeAddress },
    { headers: { "X-Session-Token": token } }
  );
  return response.data as { success: boolean; txHash?: string };
}

function mapLog(l: Record<string, unknown>) {
  return {
    user:         (l.user ?? l.address ?? "") as string,
    fileId:       (l.file_id ?? l.fileId ?? "") as string,
    action:       (l.action ?? "") as string,
    ipAddress:    (l.ip_address ?? l.ipAddress ?? "") as string,
    timestamp:    (l.timestamp ?? 0) as number,
    success:      (l.success ?? true) as boolean,
    anomalyFlag:  (l.anomaly_flag ?? l.anomalyFlag ?? false) as boolean,
    anomalyLevel: (l.anomaly_level ?? l.anomalyLevel ?? undefined) as import("@/types").AnomalyLevel | undefined,
    pending:      (l.pending ?? false) as boolean,
  };
}

export async function getAuditLogs(
  fileId: string,
  userAddress: string,
  page = 0,
  pageSize = 20
): Promise<AuditLogsResponse> {
  const token = await getOrCreateSession(userAddress);
  const response = await apiClient.get(`/audit/${fileId}`, {
    params: { page, page_size: pageSize },
    headers: { "X-Session-Token": token },
  });
  const d = response.data;
  const raw: Record<string, unknown>[] = d.logs ?? d.anomalies ?? [];
  return {
    page: d.page ?? page,
    pageSize: d.page_size ?? pageSize,
    logs: raw.map(mapLog)
  };
}

export async function getAllAuditLogs(
  userAddress: string,
  page = 0,
  pageSize = 50
): Promise<AuditLogsResponse> {
  const token = await getOrCreateSession(userAddress);
  const response = await apiClient.get("/audit/all", {
    params: { page, page_size: pageSize },
    headers: { "X-Session-Token": token },
  });
  const d = response.data;
  const raw: Record<string, unknown>[] = d.logs ?? d.anomalies ?? [];
  return {
    page: d.page ?? page,
    pageSize: d.page_size ?? pageSize,
    totalCount:   d.total_count   ?? undefined,
    hasMore:      d.has_more      ?? undefined,
    stats:        d.stats         ?? undefined,
    levelCounts:  d.level_counts  ?? undefined,
    actionCounts: d.action_counts ?? undefined,
    logs: raw.map(mapLog)
  };
}

export async function getAnomalyLogs(
  userAddress: string,
  page = 0,
  pageSize = 50
): Promise<AuditLogsResponse> {
  const token = await getOrCreateSession(userAddress);
  const response = await apiClient.get("/audit/anomalies", {
    params: { page, page_size: pageSize },
    headers: { "X-Session-Token": token },
  });
  const d = response.data;
  const raw: Record<string, unknown>[] = d.anomalies ?? d.logs ?? [];
  return {
    page: d.page ?? page,
    pageSize: d.page_size ?? pageSize,
    anomalies: raw.map(mapLog)
  };
}

export async function getHealth(): Promise<HealthResponse> {
  const response = await apiClient.get<HealthResponse>("/health");
  return response.data;
}

export async function getStorageStats(): Promise<{ total_bytes: number; total_objects: number }> {
  const response = await apiClient.get("/storage/stats");
  return response.data;
}

export default apiClient;