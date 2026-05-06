"use client";

import { useState, useCallback } from "react";
import { useAccount } from "wagmi";
import { uploadFile } from "@/lib/api";
import type { UploadResponse, FileRecord } from "@/types";

export function useUpload() {
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
    if (!file)                         { setError("Please select a file."); return; }
    if (file.size === 0)               { setError("The selected file is empty."); return; }
    if (!password)                     { setError("Please enter an encryption password."); return; }
    if (password !== confirmPassword)  { setError("Passwords do not match."); return; }
    if (password.length < 8)          { setError("Password must be at least 8 characters."); return; }

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
        fileId:    response.fileId,
        fileName:  response.fileName,
        fileSize:  response.fileSize,
        fileHash:  response.fileHash,
        owner:     address ?? "",
        timestamp: Date.now() / 1000,
        isActive:  true,
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
      setError(err instanceof Error ? err.message : "Upload failed");
      setProgress(0);
    } finally {
      setUploading(false);
    }
  }, [file, password, confirmPassword, address]);

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
    handleFileSelect,
    handleSubmit,
    setPassword,
    setConfirmPassword,
  };
}
