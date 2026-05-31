"use client";

import { useState, useCallback } from "react";
import { useAccount, useChainId } from "wagmi";
import { uploadFile } from "@/lib/api";
import type { UploadResponse, FileRecord } from "@/types";

export function useUpload() {
  const { address } = useAccount();
  const chainId = useChainId();

  const [file, setFile] = useState<File | null>(null);
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState<UploadResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanMessage, setScanMessage] = useState<string | null>(null);

  const MAX_UPLOAD_BYTES = 500 * 1024 * 1024;

  const handleFileSelect = useCallback((selected: File) => {
    if (selected.name) {
      setFile(selected);
      setResult(null);
      setError(selected.size > MAX_UPLOAD_BYTES ? "File exceeds maximum upload size of 500 MB." : null);
    } else {
      setFile(null);
    }
  }, [MAX_UPLOAD_BYTES]);

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault();
    if (!address)                          { setError("Please connect your wallet first."); return; }
    if (!file)                            { setError("Please select a file."); return; }
    if (file.size === 0)                  { setError("The selected file is empty."); return; }
    if (file.size > MAX_UPLOAD_BYTES)     { setError("File exceeds maximum upload size of 500 MB."); return; }
    if (!password)                        { setError("Please enter an encryption password."); return; }
    if (password !== confirmPassword)     { setError("Passwords do not match."); return; }
    if (password.length < 8)             { setError("Password must be at least 8 characters."); return; }

    setUploading(true);
    setScanning(true);
    setScanMessage("Scanning for threats, please wait…");
    setError(null);
    setProgress(10);

    try {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("password", password);

      const response = await uploadFile(formData, address);
      setScanning(false);
      setScanMessage(null);
      setProgress(50);

      const existing = JSON.parse(localStorage.getItem("uploadedFiles") ?? "[]") as FileRecord[];
      const newRecord: FileRecord = {
        fileId:    response.fileId,
        fileName:  response.fileName,
        fileSize:  response.fileSize,
        fileHash:  response.fileHash,
        owner:     address ?? "",
        timestamp: Date.now() / 1000,
        isActive:  true,
        chainId:   String(chainId),
        txHash:    response.txHash ?? undefined,
        aiScore:   response.aiScore,
        aiLevel:   response.aiLevel,
        numChunks: response.numChunks,
      };
      localStorage.setItem("uploadedFiles", JSON.stringify([newRecord, ...existing]));

      setResult(response);
      setProgress(100);
      setPassword("");
      setConfirmPassword("");
      setFile(null);
    } catch (err) {
      setScanning(false);
      setScanMessage(null);
      setError(err instanceof Error ? err.message : "Upload failed");
      setProgress(0);
    } finally {
      setUploading(false);
    }
  }, [file, password, confirmPassword, address, chainId]);

  const pwMatch   = confirmPassword.length > 0 && password === confirmPassword;
  const pwMismatch = confirmPassword.length > 0 && password !== confirmPassword;

  return {
    address,
    file,
    password,
    confirmPassword,
    uploading,
    progress,
    result,
    error,
    pwMatch,
    pwMismatch,
    scanning,
    scanMessage,
    handleFileSelect,
    handleSubmit,
    setPassword,
    setConfirmPassword,
  };
}
