"use client";

import { useState, useCallback } from "react";
import { useAccount } from "wagmi";
import UploadZone from "@/components/UploadZone";
import AnomalyBadge from "@/components/AnomalyBadge";
import { Card, CardContent } from "@/components/ui/card";
import { uploadFile } from "@/lib/api";
import { formatBytes, truncateAddress } from "@/lib/utils";
import { cn } from "@/lib/utils";
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
    if (!file)                          { setError("Please select a file."); return; }
    if (file.size === 0)                { setError("The selected file is empty."); return; }
    if (!password)                      { setError("Please enter an encryption password."); return; }
    if (password !== confirmPassword)   { setError("Passwords do not match."); return; }
    if (password.length < 8)           { setError("Password must be at least 8 characters."); return; }

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
        numChunks: response.numChunks,
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

  const pwMatch = confirmPassword.length > 0 && password === confirmPassword;
  const pwMismatch = confirmPassword.length > 0 && password !== confirmPassword;

  return (
    <div className="max-w-2xl mx-auto px-4 sm:px-6 lg:px-8 py-8">

      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-3">
          <span className="section-label">Secure Storage</span>
          <div className="flex-1 h-px bg-border" />
        </div>
        <h1 className="font-heading text-4xl font-bold tracking-tight">
          Secure <span className="text-primary">Upload</span>
        </h1>
        <p className="text-muted-foreground mt-2 text-sm">
          Files are chunked, encrypted, and registered on-chain
        </p>
      </div>

      <form onSubmit={handleSubmit} className="flex flex-col gap-4">

        {/* Drop zone */}
        <UploadZone
          onFileSelect={handleFileSelect}
          selectedFile={file}
          disabled={uploading}
        />

        {/* Password card */}
        <Card>
          <CardContent className="p-6 flex flex-col gap-4">
            <div className="flex items-center gap-3">
              <span className="section-label">Encryption Password</span>
              <div className="flex-1 h-px bg-border" />
            </div>

            {/* Password */}
            <div className="flex flex-col gap-1.5">
              <label className="text-sm text-muted-foreground" htmlFor="password">
                Password <span className="text-red-500">*</span>
              </label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Min. 8 characters"
                disabled={uploading}
                className={cn(
                  "w-full px-3 py-2.5 text-sm bg-muted border text-foreground placeholder-muted-foreground",
                  "focus:outline-none focus:border-primary/60 transition-colors disabled:opacity-50",
                  "font-mono rounded-sm",
                  password.length > 0 && password.length < 8 ? "border-red-500/50" : "border-border"
                )}
              />
              {password.length > 0 && password.length < 8 && (
                <p className="font-mono text-xs text-red-400">Too short — minimum 8 characters</p>
              )}
            </div>

            {/* Confirm password */}
            <div className="flex flex-col gap-1.5">
              <label className="text-sm text-muted-foreground" htmlFor="confirm-password">
                Confirm Password <span className="text-red-500">*</span>
              </label>
              <input
                id="confirm-password"
                type="password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Repeat your password"
                disabled={uploading}
                className={cn(
                  "w-full px-3 py-2.5 text-sm bg-muted border text-foreground placeholder-muted-foreground",
                  "focus:outline-none focus:border-primary/60 transition-colors disabled:opacity-50",
                  "font-mono rounded-sm",
                  pwMismatch ? "border-red-500/50" : pwMatch ? "border-emerald-500/50" : "border-border"
                )}
              />
              {pwMismatch && (
                <p className="font-mono text-xs text-red-400">Passwords do not match</p>
              )}
              {pwMatch && (
                <p className="font-mono text-xs text-emerald-400">Passwords match</p>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Wallet warning */}
        {!address && (
          <div className="flex items-start gap-3 p-4 border border-amber-500/20 bg-amber-500/5">
            <svg className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            <p className="text-amber-400 text-sm">
              Connect your wallet to register the file on the blockchain.
            </p>
          </div>
        )}

        {/* Progress */}
        {uploading && (
          <div className="flex flex-col gap-2">
            <div className="flex justify-between items-center">
              <span className="font-mono text-xs text-muted-foreground">Encrypting & uploading…</span>
              <span className="font-mono text-xs text-primary">{progress}%</span>
            </div>
            <div className="h-1 bg-muted overflow-hidden">
              <div
                className="h-full bg-primary transition-all duration-500"
                style={{ width: `${progress}%` }}
              />
            </div>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="flex items-start gap-3 p-4 border border-red-500/20 bg-red-500/5">
            <svg className="w-4 h-4 text-red-500 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            <p className="text-red-400 text-sm">{error}</p>
          </div>
        )}

        {/* Submit */}
        <button
          type="submit"
          disabled={uploading || !file}
          className={cn(
            "w-full py-3 text-sm font-heading font-semibold tracking-wide transition-all duration-200",
            "bg-primary text-primary-foreground hover:bg-primary/90",
            "disabled:opacity-30 disabled:cursor-not-allowed"
          )}
        >
          {uploading ? "Uploading…" : "Encrypt & Upload"}
        </button>
      </form>

      {/* Success result */}
      {result && (
        <Card className="mt-6 border-emerald-500/20 bg-emerald-500/[0.03]">
          <CardContent className="p-6">
            <div className="flex items-center gap-2 mb-5">
              <div className="w-5 h-5 flex items-center justify-center text-emerald-400">
                <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <h3 className="font-heading font-semibold text-emerald-400">Upload Successful</h3>
            </div>

            <div className="grid grid-cols-2 gap-4">
              {[
                { label: "File ID",  value: result.fileId,                mono: true  },
                { label: "Size",     value: formatBytes(result.fileSize), mono: false },
                { label: "Chunks",   value: String(result.numChunks),    mono: false },
              ].map(({ label, value, mono }) => (
                <div key={label}>
                  <p className="section-label mb-1">{label}</p>
                  <p className={cn("text-sm text-foreground truncate", mono && "font-mono text-xs")}>{value}</p>
                </div>
              ))}

              <div>
                <p className="section-label mb-1">AI Score</p>
                <AnomalyBadge level={(result.aiLevel as AnomalyLevel) ?? "NORMAL"} score={result.aiScore} />
              </div>

              {result.txHash && (
                <div className="col-span-2">
                  <p className="section-label mb-1">TX Hash</p>
                  <p className="font-mono text-xs text-primary truncate">{result.txHash}</p>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
