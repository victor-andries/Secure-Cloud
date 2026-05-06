interface Props {
  shareAddress: string;
  sharePermission: "READ" | "WRITE" | "FULL";
  onAddressChange: (v: string) => void;
  onPermissionChange: (v: "READ" | "WRITE" | "FULL") => void;
  onConfirm: () => void;
  onClose: () => void;
  loading: boolean;
  errorMessage?: string;
}

export default function ShareModal({
  shareAddress, sharePermission,
  onAddressChange, onPermissionChange,
  onConfirm, onClose, loading, errorMessage,
}: Props) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm px-4">
      <div className="glass-strong rounded-2xl p-6 w-full max-w-md">
        <h3 className="text-white font-semibold mb-4">Grant Access</h3>
        <div className="flex flex-col gap-3">
          <input
            type="text"
            value={shareAddress}
            onChange={(e) => onAddressChange(e.target.value)}
            placeholder="0x... wallet address"
            className="w-full px-4 py-2.5 rounded-xl text-sm bg-white/5 border border-white/10 text-white placeholder-gray-600 focus:outline-none focus:border-primary-500/60"
          />
          <select
            value={sharePermission}
            onChange={(e) => onPermissionChange(e.target.value as "READ" | "WRITE" | "FULL")}
            className="w-full px-4 py-2.5 rounded-xl text-sm bg-[#1a1a2e] border border-white/10 text-white focus:outline-none focus:border-primary-500/60"
          >
            <option value="READ">READ — view only</option>
            <option value="WRITE">WRITE — view and modify</option>
            <option value="FULL">FULL — complete access</option>
          </select>
        </div>
        {errorMessage && <p className="text-danger-400 text-sm mt-3">{errorMessage}</p>}
        <div className="flex gap-3 mt-4">
          <button
            onClick={onClose}
            className="flex-1 py-2 rounded-xl text-sm text-gray-400 hover:text-white bg-white/5 hover:bg-white/10 transition-all"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            disabled={loading || !shareAddress}
            className="flex-1 py-2 rounded-xl text-sm font-semibold bg-primary-600 hover:bg-primary-500 text-white disabled:opacity-50 transition-all"
          >
            {loading ? "Granting..." : "Grant Access"}
          </button>
        </div>
      </div>
    </div>
  );
}
