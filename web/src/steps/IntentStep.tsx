import { useEffect } from 'react';
import {
  Skeleton,
  Stack,
  StackItem,
  Title,
} from '@patternfly/react-core';
import { useSession } from '@/context/SessionContext';
import { AnalysisView } from '@/components/AnalysisView';
import { JobProgress } from '@/components/JobProgress';
import { StatTiles } from '@/components/StatTiles';
import { DismissibleAlert } from '@/components/DismissibleAlert';

export function IntentStep() {
  const {
    summary,
    analysis,
    analysisStarted,
    ensureAnalysis,
    job,
    error,
    setError,
  } = useSession();

  useEffect(() => {
    ensureAnalysis().catch((e: Error) => setError(e.message));
  }, [ensureAnalysis, setError]);

  const busy = analysisStarted && !analysis;

  return (
    <Stack hasGutter>
      <StackItem>
        <Title headingLevel="h1" size="2xl">
          NSX Intent
        </Title>
        <p style={{ marginTop: 8, color: 'var(--pf-t--global--text--color--subtle)' }}>
          Review collected configuration, connectivity, and DFW lint findings.
        </p>
      </StackItem>

      {error ? (
        <StackItem>
          <DismissibleAlert
            variant="danger"
            title={error}
            isInline
            resetKey={error}
            onDismiss={() => setError(null)}
          />
        </StackItem>
      ) : null}

      {summary ? (
        <StackItem>
          <StatTiles
            items={[
              { label: 'Virtual Machines', value: summary.vmCount ?? 0 },
              { label: 'Groups', value: summary.groupCount ?? 0 },
              { label: 'Segments', value: summary.segmentCount ?? 0 },
              { label: 'DFW Rules', value: summary.dfwRuleCount ?? 0 },
              { label: 'Services', value: summary.serviceCount ?? 0 },
            ]}
          />
          {summary.warnings?.length ? (
            <DismissibleAlert variant="warning" title="Configuration warnings" isInline style={{ marginTop: 12 }}>
              {summary.warnings.join(' · ')}
            </DismissibleAlert>
          ) : null}
        </StackItem>
      ) : (
        <StackItem>
          <Skeleton height="80px" />
        </StackItem>
      )}

      <StackItem>
        <JobProgress job={job} title="NSX analysis" />
      </StackItem>

      {busy ? (
        <StackItem>
          <Skeleton height="200px" />
        </StackItem>
      ) : null}

      {analysis ? (
        <StackItem>
          <AnalysisView analysis={analysis} />
        </StackItem>
      ) : null}
    </Stack>
  );
}
