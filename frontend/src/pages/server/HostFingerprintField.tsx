interface Props {
  value: string;
  onChange: (value: string) => void;
}

export default function HostFingerprintField({ value, onChange }: Props) {
  return (
    <div className="input-group">
      <label className="input-label" htmlFor="ssh-host-fingerprint">SSH host fingerprint</label>
      <input id="ssh-host-fingerprint" className="input input-mono" value={value}
        placeholder="SHA256:…" spellCheck={false} autoComplete="off" required
        aria-describedby="ssh-host-fingerprint-help"
        onChange={e => onChange(e.target.value)} />
      <span id="ssh-host-fingerprint-help" className="text-muted">
        Введите отпечаток ключа хоста, полученный через доверенный доступ к VPS.
      </span>
    </div>
  );
}
