import ExpiryDateField from './ExpiryDateField';

interface Props {
  expiryDate: string;
  dailyLimitMb: string;
  onExpiryChange: (v: string) => void;
  onLimitChange: (v: string) => void;
}

export default function LimitFields({ expiryDate, dailyLimitMb, onExpiryChange, onLimitChange }: Props) {
  const mb = Number(dailyLimitMb) || 0;

  return (
    <>
      <ExpiryDateField value={expiryDate} onChange={onExpiryChange} />

      <div className="input-group">
        <label className="input-label">Суточный лимит трафика, МБ (0 — без лимита)</label>
        <input className="input input-mono" type="number" min={0}
          value={dailyLimitMb} onChange={e => onLimitChange(e.target.value)} />
        <div className="text-muted mono" style={{ fontSize: 10, marginTop: 4 }}>
          {mb > 0
            ? '// при исчерпании доступ приостанавливается до начала новых суток; конфиг остаётся рабочим'
            : '// трафик не ограничен'}
        </div>
      </div>
    </>
  );
}
