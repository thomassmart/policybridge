const API = '/api/v1';

async function parseJson(res: Response): Promise<Record<string, unknown>> {
  try {
    return (await res.json()) as Record<string, unknown>;
  } catch {
    return {};
  }
}

export async function api<T = unknown>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    method,
    credentials: 'same-origin',
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await parseJson(res);
  if (!res.ok) {
    throw new Error((data.error as string) || `HTTP ${res.status}`);
  }
  return data as T;
}

export async function apiUpload<T = unknown>(path: string, fileText: string): Promise<T> {
  const res = await fetch(`${API}${path}`, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: fileText,
  });
  const data = await parseJson(res);
  if (!res.ok) {
    throw new Error((data.error as string) || `HTTP ${res.status}`);
  }
  return data as T;
}

export async function downloadPost(path: string, filename: string): Promise<void> {
  const res = await fetch(`${API}${path}`, {
    method: 'POST',
    credentials: 'same-origin',
  });
  if (!res.ok) {
    const data = await parseJson(res);
    throw new Error((data.error as string) || `HTTP ${res.status}`);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function downloadGet(path: string, filename: string): void {
  const a = document.createElement('a');
  a.href = `${API}${path}`;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
}
