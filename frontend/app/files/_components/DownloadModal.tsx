interface Props {
  password: string;
  onPasswordChange: (v: string) => void;
  onConfirm: () => void;
  onClose: () => void;
  loading: boolean;
  errorMessage?: string;
}

export default function DownloadModal({ password, onPasswordChange, onConfirm, onClose, loading, errorMessage }: Props) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm px-4">
      <div className="glass-strong rounded-2xl p-6 w-full max-w-md">
        <h3 className="text-white font-semibold mb-4">Download File</h3>
        <p className="text-gray-400 text-sm mb-4">
          Enter your encryption password to decrypt and download this file.
        </p>
        <input
          type="password"
          value={password}
          onChange={(e) => onPasswordChange(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && onConfirm()}
          placeholder="Encryption password"
          className="w-full px-4 py-2.5 rounded-xl text-sm bg-white/5 border border-white/10 text-white placeholder-gray-600 focus:outline-none focus:border-primary-500/60 mb-4"
          autoFocus
        />
        {errorMessage && <p className="text-danger-400 text-sm mb-3">{errorMessage}</p>}
        <div className="flex gap-3">
          <button
            onClick={onClose}
            className="flex-1 py-2 rounded-xl text-sm text-gray-400 hover:text-white bg-white/5 hover:bg-white/10 transition-all"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={loading || !password}
            className="flex-1 py-2 rounded-xl text-sm font-semibold bg-primary-600 hover:bg-primary-500 text-white disabled:opacity-50 transition-all"
          >
            {loading ? "Decrypting..." : "Download"}
          </button>
        </div>
      </div>
    </div>
  );
}
