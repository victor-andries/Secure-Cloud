"use client";

import { useCallback, useState } from "react";
import { formatBytes } from "@/lib/utils";
import { cn } from "@/lib/utils";

interface UploadZoneProps {
  onFileSelect: (file: File) => void;
  selectedFile?: File | null;
  disabled?: boolean;
}

export default function UploadZone({ onFileSelect, selectedFile, disabled = false }: UploadZoneProps) {
  const [isDragging, setIsDragging] = useState(false);

  const handleDragOver = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    if (!disabled) setIsDragging(true);
  }, [disabled]);

  const handleDragLeave = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      setIsDragging(false);
      if (disabled) return;
      const file = e.dataTransfer.files[0];
      if (file) onFileSelect(file);
    },
    [onFileSelect, disabled]
  );

  const handleFileInput = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) onFileSelect(file);
    },
    [onFileSelect]
  );

  return (
    <div
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      onClick={() => { if (!disabled) document.getElementById("file-input")?.click(); }}
      className={cn(
        "relative border-2 border-dashed p-12 flex flex-col items-center justify-center gap-4 transition-all duration-200 cursor-pointer select-none",
        disabled
          ? "opacity-40 cursor-not-allowed border-border bg-card"
          : isDragging
            ? "border-primary bg-primary/5"
            : selectedFile
              ? "border-emerald-500/50 bg-emerald-500/5"
              : "border-border bg-card hover:border-primary/40 hover:bg-primary/[0.03]"
      )}
    >
      <input
        id="file-input"
        type="file"
        className="hidden"
        onChange={handleFileInput}
        disabled={disabled}
      />

      {selectedFile ? (
        <>
          <div className="w-14 h-14 flex items-center justify-center border border-emerald-500/40 text-emerald-400 bg-emerald-500/10">
            <svg className="w-7 h-7" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <div className="text-center">
            <p className="font-heading text-lg font-semibold text-foreground">{selectedFile.name}</p>
            <p className="font-mono text-sm text-muted-foreground mt-1">{formatBytes(selectedFile.size)}</p>
          </div>
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              const input = document.getElementById("file-input") as HTMLInputElement;
              if (input) input.value = "";
              onFileSelect(new File([], ""));
            }}
            className="font-mono text-xs text-muted-foreground hover:text-primary underline transition-colors"
          >
            change file
          </button>
        </>
      ) : (
        <>
          <div className={cn(
            "w-14 h-14 flex items-center justify-center border transition-colors",
            isDragging
              ? "border-primary/60 bg-primary/10 text-primary"
              : "border-border bg-muted text-muted-foreground"
          )}>
            <svg className="w-7 h-7" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round"
                d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
            </svg>
          </div>
          <div className="text-center">
            <p className="font-heading font-semibold text-foreground">
              {isDragging ? "Drop your file here" : "Drag & drop a file here"}
            </p>
            <p className="text-muted-foreground text-sm mt-1">
              or <span className="text-primary">browse files</span>
            </p>
          </div>
          <p className="font-mono text-xs text-muted-foreground/60">
            Files are split into 10MB chunks and encrypted
          </p>
        </>
      )}
    </div>
  );
}
