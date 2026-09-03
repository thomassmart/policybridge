import {
  Button,
  Card,
  CardBody,
  CardTitle,
  Grid,
  GridItem,
  Stack,
  StackItem,
  Title,
} from '@patternfly/react-core';
import { downloadPost } from '@/api/client';
import { useSession } from '@/context/SessionContext';
import { DismissibleAlert } from '@/components/DismissibleAlert';

export function ExportStep() {
  const { sessionId, error, setError } = useSession();

  const exportYaml = async () => {
    if (!sessionId) return;
    await downloadPost(`/sessions/${sessionId}/export/yaml`, 'policybridge-export.yaml');
  };

  const exportZip = async () => {
    if (!sessionId) return;
    await downloadPost(`/sessions/${sessionId}/export/kustomize`, 'policybridge-export.zip');
  };

  return (
    <Stack hasGutter>
      <StackItem>
        <Title headingLevel="h1" size="2xl">
          Export
        </Title>
        <p style={{ marginTop: 8, color: 'var(--pf-t--global--text--color--subtle)' }}>
          Download generated resources in your preferred format.
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

      <StackItem>
        <Grid hasGutter>
          <GridItem md={6}>
            <Card>
              <CardTitle>Apply-ready YAML</CardTitle>
              <CardBody>
                Single multi-document YAML file in safe application order.
                <div style={{ marginTop: 16 }}>
                  <Button variant="primary" onClick={() => exportYaml()}>
                    Download YAML
                  </Button>
                </div>
              </CardBody>
            </Card>
          </GridItem>
          <GridItem md={6}>
            <Card>
              <CardTitle>GitOps Kustomize ZIP</CardTitle>
              <CardBody>
                ZIP with base, environment overlays, and comparison reports.
                <div style={{ marginTop: 16 }}>
                  <Button variant="primary" onClick={() => exportZip()}>
                    Download ZIP
                  </Button>
                </div>
              </CardBody>
            </Card>
          </GridItem>
        </Grid>
      </StackItem>
    </Stack>
  );
}
