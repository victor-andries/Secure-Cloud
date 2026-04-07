"use client";

import { useEffect, useState, useCallback } from "react";
import { useAccount } from "wagmi";
import FileCard from "@/components/FileCard";
import { downloadFile, grantAccess, deleteFile } from "@/lib/api";
import type { FileRecord } from "@/types";

export default function FilesPage() {
  const { address } = useAccount();
  const [files, setFiles] = useState<FileRecord[]>([]);
  const [downloadModal, setDownloadModal] = useState<string | null>(null);
  const [shareModal, setShareModal] = useState<string | null>(null);
  const [password, setPassword] = useState("");
  const [shareAddress, setShareAddress] = useState("");
  const [sharePermission, setSharePermission] = useState<"READ" | "WRITE" | "FULL">("READ");
  const [actionLoading, setActionLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  // Load files from localStorage
  useEffect(() => {
    const stored = localStorage.getItem("uploadedFiles");
    if (stored) {
      try {
        setFiles(JSON.parse(stored) as FileRecord[]);
      } catch {
        setFiles([]);
      }
    }
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
    setActionMessage(null);
    try {
      await deleteFile(fileId, address ?? "anonymous");
      const updated = files.filter((f) => f.fileId !== fileId);
      setFiles(updated);
      localStorage.setItem("uploadedFiles", JSON.stringify(updated));
      setActionMessage({ type: "success", text: "File deleted successfully." });
    } catch (err) {
      setActionMessage({ type: "error", text: err instanceof Error ? err.message : "Delete failed" });
    } finally {
      setActionLoading(false);
    }
  }, [files, address]);

  const executeDownload = useCallback(async () => {
    if (!downloadModal || !password) return;
    setActionLoading(true);
    setActionMessage(null);
    try {
      const result = await downloadFile(downloadModal, password, address ?? "anonymous");
      // Decode base64 and trigger browser download
      const fileRecord = files.find((f) => f.fileId === downloadModal);
      const binaryString = atob(result.data);
      const bytes = new Uint8Array(binaryString.length);
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
      }
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
      await grantAccess(shareModal, shareAddress, sharePermission);
      setShareModal(null);
      setShareAddress("");
      setActionMessage({ type: "success", text: `Access granted to ${shareAddress}` });
    } catch (err) {
      setActionMessage({ type: "error", text: err instanceof Error ? err.message : "Failed to grant access" });
    } finally {
      setActionLoading(false);
    }
  }, [shareModal, shareAddress, sharePermission]);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white">
            My <span className="text-gradient">Files</span>
          </h1>
          <p className="text-gray-400 mt-1">{files.length} encrypted file{files.length !== 1 ? "s" : ""} stored</p>
        </div>
        <a
          href="/upload"
          className="px-4 py-2 rounded-xl text-sm font-semibold bg-primary-600 hover:bg-primary-500 text-white transition-all duration-200"
        >
          + Upload File
        </a>
      </div>

      {/* Action message */}
      {actionMessage && (
        <div className={`mb-6 flex items-center gap-3 p-4 rounded-xl border ${
          actionMessage.type === "success"
            ? "bg-success-500/10 border-success-500/20 text-success-400"
            : "bg-danger-500/10 border-danger-500/20 text-danger-400"
        }`}>
          <span>{actionMessage.text}</span>
          <button onClick={() => setActionMessage(null)} className="ml-auto text-gray-500 hover:text-white">✕</button>
        </div>
      )}

      {files.length === 0 ? (
        <div className="glass rounded-2xl p-16 text-center">
          <div className="w-16 h-16 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center mx-auto mb-4">
            <svg className="w-8 h-8 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                d="M5 19a2 2 0 01-2-2V7a2 2 0 012-2h4l2 2h4a2 2 0 012 2v1M5 19h14a2 2 0 002-2v-5a2 2 0 00-2-2H9a2 2 0 00-2 2v5a2 2 0 01-2 2z" />
            </svg>
          </div>
          <p className="text-gray-400 font-medium">No files uploaded yet</p>
          <p className="text-gray-600 text-sm mt-1">Upload your first file to get started</p>
          <a href="/upload" className="inline-block mt-4 px-4 py-2 rounded-xl text-sm font-semibold bg-primary-600 hover:bg-primary-500 text-white transition-all">
            Upload a file
          </a>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
          {files.map((file) => (
            <FileCard
              key={file.fileId}
              file={file}
              onDownload={handleDownload}
              onShare={handleShare}
              onDelete={handleDelete}
            />
          ))}
        </div>
      )}

      {/* Download Modal */}
      {downloadModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm px-4">
          <div className="glass-strong rounded-2xl p-6 w-full max-w-md">
            <h3 className="text-white font-semibold mb-4">Download File</h3>
            <p className="text-gray-400 text-sm mb-4">Enter your encryption password to decrypt and download this file.</p>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && executeDownload()}
              placeholder="Encryption password"
              className="w-full px-4 py-2.5 rounded-xl text-sm bg-white/5 border border-white/10 text-white placeholder-gray-600 focus:outline-none focus:border-primary-500/60 mb-4"
              autoFocus
            />
            {actionMessage?.type === "error" && (
              <p className="text-danger-400 text-sm mb-3">{actionMessage.text}</p>
            )}
            <div className="flex gap-3">
              <button onClick={() => setDownloadModal(null)} className="flex-1 py-2 rounded-xl text-sm text-gray-400 hover:text-white bg-white/5 hover:bg-white/10 transition-all">
                Cancel
              </button>
              <button
                onClick={executeDownload}
                disabled={actionLoading || !password}
                className="flex-1 py-2 rounded-xl text-sm font-semibold bg-primary-600 hover:bg-primary-500 text-white disabled:opacity-50 transition-all"
              >
                {actionLoading ? "Decrypting..." : "Download"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Share Modal */}
      {shareModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm px-4">
          <div className="glass-strong rounded-2xl p-6 w-full max-w-md">
            <h3 className="text-white font-semibold mb-4">Grant Access</h3>
            <div className="flex flex-col gap-3">
              <input
                type="text"
                value={shareAddress}
                onChange={(e) => setShareAddress(e.target.value)}
                placeholder="0x... wallet address"
                className="w-full px-4 py-2.5 rounded-xl text-sm bg-white/5 border border-white/10 text-white placeholder-gray-600 focus:outline-none focus:border-primary-500/60"
              />
              <select
                value={sharePermission}
                onChange={(e) => setSharePermission(e.target.value as "READ" | "WRITE" | "FULL")}
                className="w-full px-4 py-2.5 rounded-xl text-sm bg-[#1a1a2e] border border-white/10 text-white focus:outline-none focus:border-primary-500/60"
              >
                <option value="READ">READ — view only</option>
                <option value="WRITE">WRITE — view and modify</option>
                <option value="FULL">FULL — complete access</option>
              </select>
            </div>
            {actionMessage?.type === "error" && (
              <p className="text-danger-400 text-sm mt-3">{actionMessage.text}</p>
            )}
            <div className="flex gap-3 mt-4">
              <button onClick={() => setShareModal(null)} className="flex-1 py-2 rounded-xl text-sm text-gray-400 hover:text-white bg-white/5 hover:bg-white/10 transition-all">
                Cancel
              </button>
              <button
                onClick={executeShare}
                disabled={actionLoading || !shareAddress}
                className="flex-1 py-2 rounded-xl text-sm font-semibold bg-primary-600 hover:bg-primary-500 text-white disabled:opacity-50 transition-all"
              >
                {actionLoading ? "Granting..." : "Grant Access"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
