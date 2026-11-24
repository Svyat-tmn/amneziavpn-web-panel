import { z } from 'zod';

// Calendar dates use the panel's TZ. The selected day is included.
export const expiryDateSchema = z.string().date().nullable().optional();

export function expiryTimestamp(date: string | null | undefined, days = 0): number | null {
  if (date === undefined) return days > 0 ? Math.floor(Date.now() / 1000) + days * 86400 : null;
  if (date === null) return null;
  const end = new Date(`${date}T00:00:00`);
  end.setDate(end.getDate() + 1);
  return Math.floor(end.getTime() / 1000);
}

export function expiryCalendarDate(timestamp: number | null | undefined): string | null {
  if (!timestamp) return null;
  const date = new Date(timestamp * 1000 - 1);
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${date.getFullYear()}-${month}-${day}`;
}
