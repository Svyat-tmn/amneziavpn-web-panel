import { useId } from 'react';

export function toDateInput(date: Date): string {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

export function formatExpiryDate(date: string): string {
  return new Date(`${date}T12:00:00`).toLocaleDateString('ru-RU');
}

function dateInMonths(months: number): string {
  const today = new Date();
  const destination = new Date(today.getFullYear(), today.getMonth() + months, 1);
  const lastDay = new Date(destination.getFullYear(), destination.getMonth() + 1, 0).getDate();
  destination.setDate(Math.min(today.getDate(), lastDay));
  return toDateInput(destination);
}

interface Props {
  value: string;
  onChange: (value: string) => void;
  legacyDays?: number;
}

export default function ExpiryDateField({ value, onChange, legacyDays }: Props) {
  const id = useId();
  return (
    <div className="input-group">
      <label className="input-label" htmlFor={id}>Срок действия до</label>
      <input id={id} className="input input-mono" type="date"
        value={value} onChange={e => onChange(e.target.value)} />
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        {[[1, 'Месяц'], [6, '6 месяцев'], [12, 'Год']].map(([months, label]) => (
          <button type="button" className="btn btn-outline btn-sm" key={months}
            onClick={() => onChange(dateInMonths(Number(months)))}>{label}</button>
        ))}
        <button type="button" className="btn btn-outline btn-sm" onClick={() => onChange('')}>Бессрочно</button>
      </div>
      <small className="text-muted">
        {legacyDays ? `Текущая настройка: ${legacyDays} дн. с выпуска клиента.`
          : value ? 'Дата включительно по часовому поясу панели. После срока доступ приостановится, конфиг сохранится.'
            : 'Без ограничения по сроку.'}
      </small>
    </div>
  );
}
