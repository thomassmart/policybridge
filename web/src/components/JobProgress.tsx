import { useEffect, useState } from 'react';
import {
  Button,
  ExpandableSection,
  Progress,
  ProgressSize,
  Stack,
  StackItem,
} from '@patternfly/react-core';
import type { JobState } from '@/api/types';

interface JobProgressProps {
  job: JobState;
  title?: string;
}

export function JobProgress({ job, title }: JobProgressProps) {
  const [expanded, setExpanded] = useState(false);
  const [dismissed, setDismissed] = useState(false);

  useEffect(() => {
    if (job.running) {
      setExpanded(true);
      setDismissed(false);
    }
  }, [job.running, job.label]);

  const logs = job.logs ?? [];
  if (!job.running && !logs.length) {
    return null;
  }

  if (dismissed) {
    return null;
  }

  return (
    <Stack hasGutter>
      {job.running && (
        <StackItem>
          <Progress
            value={job.progress}
            title={title || job.label}
            size={ProgressSize.sm}
            measureLocation="outside"
            aria-label={job.message}
          />
          <p style={{ marginTop: 8, fontSize: '0.875rem' }}>{job.message}</p>
        </StackItem>
      )}
      {logs.length > 0 ? (
        <StackItem>
          <div className="pb-job-progress__log">
            <ExpandableSection
              toggleText="Activity log"
              isExpanded={expanded}
              onToggle={(_event, isExpanded) => setExpanded(isExpanded)}
            >
              <pre
                style={{
                  margin: 0,
                  padding: 12,
                  background: 'var(--pf-t--global--background--color--secondary--default)',
                  borderRadius: 4,
                  fontSize: '0.75rem',
                  maxHeight: 200,
                  overflow: 'auto',
                }}
              >
                {logs.join('\n')}
              </pre>
            </ExpandableSection>
            {!job.running ? (
              <Button
                variant="plain"
                aria-label="Dismiss activity log"
                onClick={() => setDismissed(true)}
              >
                Dismiss
              </Button>
            ) : null}
          </div>
        </StackItem>
      ) : null}
    </Stack>
  );
}
