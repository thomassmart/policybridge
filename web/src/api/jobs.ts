import { api } from './client';
import type { Job, JobState } from './types';

export type JobUpdate = (state: Partial<JobState>) => void;

export async function pollJob(
  sessionId: string,
  jobId: string,
  label: string,
  onUpdate: JobUpdate,
): Promise<Job> {
  const start = Date.now();
  const logs: string[] = [];
  onUpdate({ label, running: true, progress: 0, message: 'Starting…', logs: [], error: undefined });

  let lastLogCount = 0;
  for (let i = 0; i < 1800; i++) {
    const job = await api<Job>('GET', `/sessions/${sessionId}/jobs/${jobId}`);
    const elapsed = Math.floor((Date.now() - start) / 1000);
    const statusMsg = job.message || job.state;
    const progress = typeof job.progress === 'number' ? job.progress : 0;

    if (Array.isArray(job.logs) && job.logs.length > lastLogCount) {
      for (let li = lastLogCount; li < job.logs.length; li++) {
        logs.push(job.logs[li]);
      }
      lastLogCount = job.logs.length;
    }

    if (job.state === 'running') {
      onUpdate({
        label,
        running: true,
        progress,
        message: `${statusMsg} (${elapsed}s)`,
        logs: [...logs],
      });
      await new Promise((r) => setTimeout(r, 1000));
      continue;
    }

    if (job.state === 'completed') {
      onUpdate({
        label,
        running: false,
        progress: 100,
        message: `Completed (${elapsed}s)`,
        logs: [...logs, `${label} completed`],
        error: undefined,
      });
      return job;
    }

    const err = job.error || job.message || `${label} ${job.state}`;
    onUpdate({
      label,
      running: false,
      progress,
      message: err,
      logs: [...logs, `${label} failed: ${err}`],
      error: err,
    });
    return job;
  }

  const err = `${label} timed out`;
  onUpdate({ label, running: false, message: err, logs: [...logs, err], error: err });
  throw new Error(err);
}

export async function runJob(
  sessionId: string,
  startPath: string,
  startBody: unknown | undefined,
  label: string,
  onUpdate: JobUpdate,
): Promise<Job> {
  const { jobId } = await api<{ jobId: string }>('POST', startPath, startBody);
  return pollJob(sessionId, jobId, label, onUpdate);
}
