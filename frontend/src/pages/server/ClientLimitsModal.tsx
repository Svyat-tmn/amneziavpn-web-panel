import { useState } from 'react';
import { clientsApi, type ClientRecord } from '../../api';
import LimitFields from './LimitFields';
import { formatBytes } from './format';
import { toDateInput } from './ExpiryDateField';

interface Props {
  client: ClientRecord;
  onClose: () => void;
  onSaved: (updated: ClientRecord) => void;
}

export default function ClientLimitsModal({ client, onClose, onSaved }: Props) {
  const expired = !!client.expires_at && client.expires_at <= Date.now() / 1000;
  const [expiryDate, setExpiryDate] = useState<string | undefined>();
  const [dailyLimitMb, setDailyLimitMb] = useState(String(Math.round(client.daily_limit_bytes / (1024 * 1024))));
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const submit = async () => {
    setLoading(true);
    setError('');
    try {
      const r = await clientsApi.setLimits(client.id, {
        expiryDate: expiryDate === undefined ? undefined : expiryDate || null,
        dailyLimitMb: Number(dailyLimitMb) || 0,
      });
      onSaved({ ...client, ...r.data });
    } catch (e: any) {
      setError(e.response?.data?.error || 'Не удалось сохранить лимиты');
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={e => e.target === e.currentTarget && onClose()}>
      <div className="modal" style={{ width: 420, maxHeight: '85vh', overflowY: 'auto' }}>
        <div className="modal-title">Лимиты · {client.name}</div>
        {error && <div className="notice notice-error" style={{ marginBottom: 12 }}>{error}</div>}

        {expired ? (
          <div className="notice" style={{ marginBottom: 12 }}>
            Срок действия истёк. Продлите его, чтобы восстановить доступ с прежним конфигом.
          </div>
        ) : !!client.suspended_at && (
          <div className="notice" style={{ marginBottom: 12 }}>
            Сейчас приостановлен: за сегодня израсходовано {formatBytes(client.used_today)}.
            Поднимите лимит — доступ вернётся сразу, ждать полуночи не нужно.
          </div>
        )}

        <LimitFields
          expiryDate={expiryDate ?? client.expires_on ?? (client.expires_at ? toDateInput(new Date((client.expires_at - 1) * 1000)) : '')}
          dailyLimitMb={dailyLimitMb}
          onExpiryChange={setExpiryDate}
          onLimitChange={setDailyLimitMb}
        />

        <div className="modal-actions">
          <button className="btn btn-outline" onClick={onClose}>Отмена</button>
          <button className="btn btn-primary" onClick={submit} disabled={loading}
            title="Применить лимиты сразу: если клиент приостановлен, а лимит поднят — он вернётся немедленно">
            {loading ? <span className="spinner" /> : 'Сохранить'}
          </button>
        </div>
      </div>
    </div>
  );
}
