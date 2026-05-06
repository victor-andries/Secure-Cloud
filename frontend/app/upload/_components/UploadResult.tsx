import AnomalyBadge from "@/components/AnomalyBadge";
import { Card, CardContent } from "@/components/ui/card";
import { formatBytes } from "@/lib/utils";
import { cn } from "@/lib/utils";
import type { UploadResponse, AnomalyLevel } from "@/types";

interface Props {
  result: UploadResponse;
}

export default function UploadResult({ result }: Props) {
  return (
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
            { label: "File ID", value: result.fileId,                mono: true  },
            { label: "Size",    value: formatBytes(result.fileSize), mono: false },
            { label: "Chunks",  value: String(result.numChunks),    mono: false },
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
  );
}
