"use client";

import FileCard from "@/components/FileCard";
import { useFiles } from "./_hooks/useFiles";
import DownloadModal from "./_components/DownloadModal";
import ShareModal from "./_components/ShareModal";

export default function FilesPage() {
  const {
    files,
    downloadModal, shareModal,
    password, shareAddress, sharePermission,
    actionLoading, actionMessage,
    deletingFileIds, deleteAllProgress,
    setDownloadModal, setShareModal,
    setPassword, setShareAddress, setSharePermission,
    setActionMessage,
    handleDownload, handleShare, handleDelete, handleDeleteAll,
    executeDownload, executeShare,
  } = useFiles();

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-white">
            My <span className="text-gradient">Files</span>
          </h1>
          <p className="text-gray-400 mt-1">
            {files.length} encrypted file{files.length !== 1 ? "s" : ""} stored
          </p>
        </div>
        <div className="flex items-center gap-2">
          {files.length > 0 && (
            <button
              onClick={handleDeleteAll}
              disabled={actionLoading}
              className="flex items-center gap-2 px-4 py-2 rounded-xl text-sm text-danger-400 bg-danger-500/10 border border-danger-500/20 hover:bg-danger-500/20 transition-all disabled:opacity-50"
            >
              {deleteAllProgress ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-danger-400/30 border-t-danger-400 rounded-full animate-spin" />
                  Deleting {deleteAllProgress.current}/{deleteAllProgress.total}…
                </>
              ) : "Delete All"}
            </button>
          )}
          <a
            href="/upload"
            className="px-4 py-2 rounded-xl text-sm font-semibold bg-primary-600 hover:bg-primary-500 text-white transition-all duration-200"
          >
            + Upload File
          </a>
        </div>
      </div>

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
              deleting={deletingFileIds.includes(file.fileId)}
            />
          ))}
        </div>
      )}

      {downloadModal && (
        <DownloadModal
          password={password}
          onPasswordChange={setPassword}
          onConfirm={executeDownload}
          onClose={() => setDownloadModal(null)}
          loading={actionLoading}
          errorMessage={actionMessage?.type === "error" ? actionMessage.text : undefined}
        />
      )}

      {shareModal && (
        <ShareModal
          shareAddress={shareAddress}
          sharePermission={sharePermission}
          onAddressChange={setShareAddress}
          onPermissionChange={setSharePermission}
          onConfirm={executeShare}
          onClose={() => setShareModal(null)}
          loading={actionLoading}
          errorMessage={actionMessage?.type === "error" ? actionMessage.text : undefined}
        />
      )}
    </div>
  );
}
