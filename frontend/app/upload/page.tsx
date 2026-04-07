"use client";

import { useState, useCallback } from "react";
import { useAccount } from "wagmi";
import UploadZone from "@/components/UploadZone";
import AnomalyBadge from "@/components/AnomalyBadge";
import { uploadFile } from "@/lib/api";
import { formatBytes, truncateAddress } from "@/lib/utils";
import type { UploadResponse, AnomalyLevel, FileRecord } from "@/types";

export default function UploadPage() {
  const { address } = useAccount();

  const [file, setFile] = useState<File | null>(null);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState<UploadResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleFileSelect = useCallback((selected: File) => {
    if (selected.name) {
      setFile(selected);
      setResult(null);
      setError(null);
    } else {
      setFile(null);
    }
  }, []);

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) { setError("Please select a file."); return; }
    if (file.size === 0) { setError("The selected file is empty (0 bytes). Please choose a file with content."); return; }
    if (!password) { setError("Please enter an encryption password."); return; }
    if (password !== confirmPassword) { setError("Passwords do not match."); return; }
    if (password.length < 8) { setError("Password must be at least 8 characters."); return; }

    setUploading(true);
    setError(null);
    setProgress(10);

    try {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("password", password);
      if (address) formData.append("user_address", address);

      setProgress(30);
      const response = await uploadFile(formData);
      setProgress(90);

      // Persist to localStorage for file list
      const existing = JSON.parse(localStorage.getItem("uploadedFiles") ?? "[]") as FileRecord[];
      const newRecord: FileRecord = {
        fileId: response.fileId,
        fileName: response.fileName,
        fileSize: response.fileSize,
        fileHash: response.fileHash,
        owner: address ?? "",
        timestamp: Date.now() / 1000,
        isActive: true,
        txHash: response.txHash ?? undefined,
        aiScore: response.aiScore,
        aiLevel: response.aiLevel,
        numChunks: response.numChunks
      };
      localStorage.setItem("uploadedFiles", JSON.stringify([newRecord, ...existing]));

      setResult(response);
      setProgress(100);
      setPassword("");
      setConfirmPassword("");
      setFile(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Upload failed");
      setProgress(0);
    } finally {
      setUploading(false);
    }
  }, [file, password, confirmPassword, address]);

  return (
    <div className="max-w-2xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white">
          Secure <span className="text-gradient">Upload</span>
        </h1>
        <p className="text-gray-400 mt-1">
          Files are chunked, AES-256-GCM encrypted, and registered on-chain
        </p>
      </div>

      <form onSubmit={handleSubmit} className="flex flex-col gap-6">
        {/* Upload Zone */}
        <UploadZone
          onFileSelect={handleFileSelect}
          selectedFile={file}
          disabled={uploading}
        />

        {/* Password fields */}
        <div className="glass rounded-2xl p-6 flex flex-col gap-4">
          <h2 className="text-white font-semibold text-sm uppercase tracking-wide">
            Encryption Password
          </h2>

          <div>
            <label className="block text-sm text-gray-400 mb-1.5" htmlFor="password">
              Password <span className="text-danger-500">*</span>
            </label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Min. 8 characters"
              disabled={uploading}
              className="
                w-full px-4 py-2.5 rounded-xl text-sm
                bg-white/5 border border-white/10
                text-white placeholder-gray-600
                focus:outline-none focus:border-primary-500/60 focus:bg-white/8
                disabled:opacity-50 transition-colors
              "
            />
          </div>

          <div>
            <label className="block text-sm text-gray-400 mb-1.5" htmlFor="confirm-password">
              Confirm Password <span className="text-danger-500">*</span>
            </label>
            <input
              id="confirm-password"
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Repeat your password"
              disabled={uploading}
              className="
                w-full px-4 py-2.5 rounded-xl text-sm
                bg-white/5 border border-white/10
                text-white placeholder-gray-600
                focus:outline-none focus:border-primary-500/60 focus:bg-white/8
                disabled:opacity-50 transition-colors
              "
            />
          </div>
        </div>

        {/* Wallet warning */}
        {!address && (
          <div className="flex items-center gap-3 p-4 rounded-xl bg-warning-500/10 border border-warning-500/20">
            <svg className="w-5 h-5 text-warning-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <p className="text-warning-400 text-sm">
              Connect your wallet to register the file on the blockchain.
            </p>
          </div>
        )}

        {/* Progress bar */}
        {uploading && (
          <div className="flex flex-col gap-2">
            <div className="flex justify-between text-xs text-gray-400">
              <span>Encrypting & uploading...</span>
              <span>{progress}%</span>
            </div>
            <div className="h-2 bg-white/5 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-primary-600 to-secondary-500 rounded-full transition-all duration-500"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="flex items-center gap-3 p-4 rounded-xl bg-danger-500/10 border border-danger-500/20">
            <svg className="w-5 h-5 text-danger-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <p className="text-danger-400 text-sm">{error}</p>
          </div>
        )}

        {/* Submit */}
        <button
          type="submit"
          disabled={uploading || !file}
          className="
            w-full py-3 rounded-xl text-sm font-semibold
            bg-primary-600 hover:bg-primary-500
            disabled:opacity-40 disabled:cursor-not-allowed
            text-white transition-all duration-200
            shadow-lg shadow-primary-500/20 hover:shadow-primary-500/40
          "
        >
          {uploading ? "Uploading..." : "Encrypt & Upload"}
        </button>
      </form>

      {/* Success result */}
      {result && (
        <div className="mt-6 glass rounded-2xl p-6 border border-success-500/20 bg-success-500/5">
          <div className="flex items-center gap-2 mb-4">
            <svg className="w-5 h-5 text-success-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <h3 className="text-success-400 font-semibold">Upload Successful</h3>
          </div>
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div>
              <p className="text-gray-500 text-xs uppercase font-medium mb-0.5">File ID</p>
              <p className="text-gray-200 font-mono text-xs truncate">{result.fileId}</p>
            </div>
            <div>
              <p className="text-gray-500 text-xs uppercase font-medium mb-0.5">Size</p>
              <p className="text-gray-200">{formatBytes(result.fileSize)}</p>
            </div>
            <div>
              <p className="text-gray-500 text-xs uppercase font-medium mb-0.5">Chunks</p>
              <p className="text-gray-200">{result.numChunks}</p>
            </div>
            <div>
              <p className="text-gray-500 text-xs uppercase font-medium mb-0.5">AI Score</p>
              <AnomalyBadge level={(result.aiLevel as AnomalyLevel) ?? "NORMAL"} score={result.aiScore} />
            </div>
            {result.txHash && (
              <div className="col-span-2">
                <p className="text-gray-500 text-xs uppercase font-medium mb-0.5">TX Hash</p>
                <p className="text-primary-400 font-mono text-xs truncate">{result.txHash}</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
