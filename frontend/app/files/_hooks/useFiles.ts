"use client";

import { useEffect, useState, useCallback, useMemo } from "react";
import { useAccount, useChainId } from "wagmi";
import { downloadFile, grantAccess, deleteFile } from "@/lib/api";
import type { FileRecord } from "@/types";

const STORAGE_KEY = "uploadedFiles";

function loadAll(): FileRecord[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const records = JSON.parse(raw) as FileRecord[];

    // TODO(migration): remove this block once all legacy entries have been cleaned up.
    // Assigns Sepolia chain ID to entries that predate the multi-chain feature.
    const migrated = records.map((r) =>
      r.chainId ? r : { ...r, chainId: "11155111" }
    );
    if (migrated.some((r, i) => r.chainId !== records[i].chainId)) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(migrated));
    }
    return migrated;
  } catch {
    return [];
  }
}

function saveAll(records: FileRecord[]) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(records));
}

export function useFiles() {
  const { address } = useAccount();
  const chainId = useChainId();
  const [allFiles, setAllFiles] = useState<FileRecord[]>([]);

  const files = useMemo(
    () => allFiles.filter((f) => f.chainId === String(chainId)),
    [allFiles, chainId]
  );
  const [downloadModal, setDownloadModal] = useState<string | null>(null);
  const [shareModal, setShareModal] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [shareAddress, setShareAddress] = useState("");
  const [sharePermission, setSharePermission] = useState<"READ" | "WRITE" | "FULL">("READ");
  const [actionLoading, setActionLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);
  const [deletingFileIds, setDeletingFileIds] = useState<string[]>([]);
  const [deleteAllProgress, setDeleteAllProgress] = useState<{ current: number; total: number } | null>(null);

  useEffect(() => {
    setAllFiles(loadAll());
  }, []);

  const handleDownload = useCallback((fileId: string) => {
    setDownloadModal(fileId);
    setPassword("");
    setActionMessage(null);
  }, []);

  const handleShare = useCallback((fileId: string) => {
    setShareModal(fileId);
    setShareAddress("");
    setActionMessage(null);
  }, []);

  const handleDelete = useCallback(async (fileId: string) => {
    if (!confirm("Permanently delete this file and all its encrypted chunks? This cannot be undone.")) return;
    setActionLoading(true);
    setDeletingFileIds((prev) => [...prev, fileId]);
    setActionMessage(null);
    try {
      await deleteFile(fileId, address ?? "anonymous");
      const updated = allFiles.filter((f) => f.fileId !== fileId);
      setAllFiles(updated);
      saveAll(updated);
      setActionMessage({ type: "success", text: "File deleted successfully." });
    } catch (err) {
      setActionMessage({ type: "error", text: err instanceof Error ? err.message : "Delete failed" });
    } finally {
      setDeletingFileIds((prev) => prev.filter((id) => id !== fileId));
      setActionLoading(false);
    }
  }, [allFiles, address]);

  const handleDeleteAll = useCallback(async () => {
    if (!confirm(`Permanently delete all ${files.length} file(s)? This cannot be undone.`)) return;
    setActionLoading(true);
    setActionMessage(null);
    const snapshot = [...files];
    const total = snapshot.length;
    setDeletingFileIds(snapshot.map((f) => f.fileId));
    setDeleteAllProgress({ current: 0, total });

    let completed = 0;
    let failed = 0;
    await Promise.all(snapshot.map(async (file) => {
      try {
        await deleteFile(file.fileId, address ?? "anonymous");
      } catch {
        failed++;
      }
      completed++;
      setDeleteAllProgress({ current: completed, total });
    }));

    const deletedIds = new Set(snapshot.map((f) => f.fileId));
    const remaining = allFiles.filter((f) => !deletedIds.has(f.fileId));
    setAllFiles(remaining);
    saveAll(remaining);
    setDeletingFileIds([]);
    setDeleteAllProgress(null);
    setActionMessage({
      type: failed === 0 ? "success" : "error",
      text: failed === 0
        ? "All files deleted."
        : `Deleted with ${failed} storage error(s) — local records cleared.`,
    });
    setActionLoading(false);
  }, [files, allFiles, address]);

  const executeDownload = useCallback(async () => {
    if (!downloadModal || !password) return;
    setActionLoading(true);
    setActionMessage(null);
    try {
      const result = await downloadFile(downloadModal, password, address ?? "anonymous");
      const fileRecord = files.find((f) => f.fileId === downloadModal);
      const binaryString = atob(result.data);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
      const blob = new Blob([bytes]);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = fileRecord?.fileName ?? `file-${downloadModal}`;
      a.click();
      URL.revokeObjectURL(url);
      setDownloadModal(null);
      setPassword("");
      setActionMessage({ type: "success", text: "Download complete!" });
    } catch (err) {
      setActionMessage({ type: "error", text: err instanceof Error ? err.message : "Download failed" });
    } finally {
      setActionLoading(false);
    }
  }, [downloadModal, password, address, files]);

  const executeShare = useCallback(async () => {
    if (!shareModal || !shareAddress) return;
    setActionLoading(true);
    setActionMessage(null);
    try {
      await grantAccess(shareModal, address ?? "", shareAddress, sharePermission);
      setShareModal(null);
      setShareAddress("");
      setActionMessage({ type: "success", text: `Access granted to ${shareAddress}` });
    } catch (err) {
      setActionMessage({ type: "error", text: err instanceof Error ? err.message : "Failed to grant access" });
    } finally {
      setActionLoading(false);
    }
  }, [shareModal, shareAddress, sharePermission]);

  return {
    files,
    downloadModal,
    shareModal,
    password,
    shareAddress,
    sharePermission,
    actionLoading,
    actionMessage,
    deletingFileIds,
    deleteAllProgress,
    setDownloadModal,
    setShareModal,
    setPassword,
    setShareAddress,
    setSharePermission,
    setActionMessage,
    handleDownload,
    handleShare,
    handleDelete,
    handleDeleteAll,
    executeDownload,
    executeShare,
  };
}
