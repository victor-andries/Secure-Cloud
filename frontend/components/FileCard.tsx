"use client";

import { formatBytes, formatTimestamp, truncateAddress } from "@/lib/utils";
import AnomalyBadge from "@/components/AnomalyBadge";
import type { FileCardProps, AnomalyLevel } from "@/types";

export default function FileCard({ file, onDownload, onShare, onDelete, deleting }: FileCardProps) {
  const level: AnomalyLevel = file.aiLevel ?? "NORMAL";

  return (
    <div className={`
      glass rounded-2xl p-5 flex flex-col gap-4 relative
      transition-all duration-200
      ${deleting ? "opacity-60" : "hover:border-primary-500/20 hover:shadow-lg hover:shadow-black/20"}
    `}>
      {deleting && (
        <div className="absolute inset-0 rounded-2xl flex items-center justify-center bg-black/30 backdrop-blur-[2px] z-10">
          <div className="flex items-center gap-2.5 px-4 py-2 rounded-xl bg-background/80 border border-white/10">
            <div className="w-4 h-4 border-2 border-danger-400/30 border-t-danger-400 rounded-full animate-spin shrink-0" />
            <span className="text-danger-300 text-xs font-medium">Deleting…</span>
          </div>
        </div>
      )}
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-10 h-10 rounded-xl bg-primary-500/20 border border-primary-500/30 flex items-center justify-center shrink-0">
            <svg className="w-5 h-5 text-primary-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
          </div>
          <div className="min-w-0">
            <p className="text-white font-semibold truncate">{file.fileName}</p>
            <p className="text-gray-500 text-xs">{formatBytes(file.fileSize)}</p>
          </div>
        </div>
        <AnomalyBadge level={level} score={file.aiScore} />
      </div>

      {/* Metadata */}
      <div className="grid grid-cols-2 gap-3 text-xs">
        <div>
          <p className="text-gray-600 uppercase tracking-wide font-medium mb-0.5">Uploaded</p>
          <p className="text-gray-300">{formatTimestamp(file.timestamp)}</p>
        </div>
        <div>
          <p className="text-gray-600 uppercase tracking-wide font-medium mb-0.5">Chunks</p>
          <p className="text-gray-300">{file.numChunks ?? "—"}</p>
        </div>
        {file.txHash && (
          <div className="col-span-2">
            <p className="text-gray-600 uppercase tracking-wide font-medium mb-0.5">TX Hash</p>
            <p className="text-primary-400 font-mono truncate" title={file.txHash}>
              {truncateAddress(file.txHash, 10, 8)}
            </p>
          </div>
        )}
        {file.owner && (
          <div className="col-span-2">
            <p className="text-gray-600 uppercase tracking-wide font-medium mb-0.5">Owner</p>
            <p className="text-gray-300 font-mono truncate">{truncateAddress(file.owner)}</p>
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="flex gap-2 pt-1 border-t border-white/5">
        <button
          onClick={() => onDownload(file.fileId)}
          disabled={deleting}
          className="
            flex-1 flex items-center justify-center gap-2
            px-3 py-2 rounded-lg text-sm font-medium
            bg-primary-600/20 hover:bg-primary-600/30
            border border-primary-500/30
            text-primary-300 transition-all duration-200
          "
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
          </svg>
          Download
        </button>
        <button
          onClick={() => onShare(file.fileId)}
          disabled={deleting}
          className="
            flex-1 flex items-center justify-center gap-2
            px-3 py-2 rounded-lg text-sm font-medium
            bg-white/5 hover:bg-white/10
            border border-white/10
            text-gray-300 transition-all duration-200
          "
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z" />
          </svg>
          Share
        </button>
        <button
          onClick={() => onDelete(file.fileId)}
          disabled={deleting}
          className="
            flex items-center justify-center
            px-3 py-2 rounded-lg text-sm font-medium
            bg-danger-500/10 hover:bg-danger-500/20
            border border-danger-500/20
            text-danger-400 transition-all duration-200
          "
          title="Delete file"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
              d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
          </svg>
        </button>
      </div>
    </div>
  );
}
