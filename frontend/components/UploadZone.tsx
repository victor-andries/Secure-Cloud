"use client";

import { useCallback, useState } from "react";
import { formatBytes } from "@/lib/utils";

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
      className={`
        relative rounded-2xl border-2 border-dashed p-10
        flex flex-col items-center justify-center gap-4
        transition-all duration-300 cursor-pointer
        ${disabled
          ? "opacity-50 cursor-not-allowed border-gray-700 bg-gray-900/20"
          : isDragging
            ? "border-primary-500 bg-primary-500/10 scale-[1.01]"
            : selectedFile
              ? "border-success-500/60 bg-success-500/5"
              : "border-gray-700 hover:border-primary-500/60 hover:bg-primary-500/5 bg-white/[0.02]"
        }
      `}
      onClick={() => {
        if (!disabled) {
          document.getElementById("file-input")?.click();
        }
      }}
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
          <div className="w-16 h-16 rounded-2xl bg-success-500/20 border border-success-500/30 flex items-center justify-center">
            <svg className="w-8 h-8 text-success-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
          </div>
          <div className="text-center">
            <p className="text-white font-semibold text-lg">{selectedFile.name}</p>
            <p className="text-gray-400 text-sm mt-1">{formatBytes(selectedFile.size)}</p>
          </div>
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              const input = document.getElementById("file-input") as HTMLInputElement;
              if (input) input.value = "";
              onFileSelect(new File([], ""));
            }}
            className="text-xs text-gray-500 hover:text-gray-300 underline transition-colors"
          >
            Change file
          </button>
        </>
      ) : (
        <>
          <div className={`
            w-16 h-16 rounded-2xl border flex items-center justify-center transition-colors
            ${isDragging
              ? "bg-primary-500/20 border-primary-500/40 text-primary-400"
              : "bg-white/5 border-white/10 text-gray-500"
            }
          `}>
            <svg className="w-8 h-8" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
            </svg>
          </div>
          <div className="text-center">
            <p className="text-white font-medium">
              {isDragging ? "Drop your file here" : "Drag & drop a file here"}
            </p>
            <p className="text-gray-500 text-sm mt-1">
              or <span className="text-primary-400 hover:text-primary-300">browse files</span>
            </p>
          </div>
          <p className="text-xs text-gray-600">
            Files are split into 10MB chunks and encrypted with AES-256-GCM
          </p>
        </>
      )}
    </div>
  );
}
