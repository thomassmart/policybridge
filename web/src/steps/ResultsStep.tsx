import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionToggle,
  Alert,
  AlertActionLink,
  Button,
  Card,
  CardBody,
  Label,
  Skeleton,
  Stack,
  StackItem,
  Title,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { useSession } from '@/context/SessionContext';
import { JobProgress } from '@/components/JobProgress';
import { StatTiles } from '@/components/StatTiles';
import { DismissibleAlert } from '@/components/DismissibleAlert';
import {
  collectComparisonFindings,
  comparisonSummary,
  displayFindingValue,
} from '@/utils/comparisonFindings';

export function ResultsStep() {
  const {
    policies,
    policyPreview,
    validation,
    loadPolicyFile,
    job,
    error,
    setError,
    runGenerateAndValidate,
  } = useSession();

  const startedRef = useRef(false);
  const [validationOpen, setValidationOpen] = useState(false);

  const startGeneration = useCallback(() => {
    startedRef.current = true;
    runGenerateAndValidate().catch(() => {
      startedRef.current = false;
    });
  }, [runGenerateAndValidate]);

  useEffect(() => {
    if (startedRef.current || policies || validation) return;
    startGeneration();
  }, [policies, validation, startGeneration]);

  const cmp = comparisonSummary(validation?.comparison);
  const findings = collectComparisonFindings(validation?.comparison);

  const busy = job.running || (!policies && !validation && !error);

  return (
    <Stack hasGutter>
      <StackItem>
        <Title headingLevel="h1" size="2xl">
          Results
        </Title>
        <p style={{ marginTop: 8, color: 'var(--pf-t--global--text--color--subtle)' }}>
          Generated Kubernetes resources from the selected NSX rules.
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
            actionLinks={
              !job.running ? (
                <AlertActionLink
                  onClick={() => {
                    startedRef.current = false;
                    startGeneration();
                  }}
                >
                  Retry generation
                </AlertActionLink>
              ) : undefined
            }
          />
        </StackItem>
      ) : null}

      <StackItem>
        <JobProgress job={job} />
      </StackItem>

      {busy && !policies ? (
        <StackItem>
          <Skeleton height="120px" />
        </StackItem>
      ) : null}

      {policies ? (
        <StackItem>
          <Title headingLevel="h2" size="lg">
            Generated resources
          </Title>
          <div style={{ marginTop: 8 }}>
            <StatTiles
              items={Object.entries(policies.resourceCounts || {}).map(([kind, count]) => ({
                label: kind,
                value: count,
              }))}
            />
          </div>
          <ul style={{ marginTop: 12 }}>
            {(policies.files || []).map((f) => (
              <li key={f}>
                <Button variant="link" isInline onClick={() => loadPolicyFile(f)}>
                  {f}
                </Button>
              </li>
            ))}
          </ul>
          {policyPreview ? (
            <Card style={{ marginTop: 16 }}>
              <CardBody>
                <Title headingLevel="h3" size="md">
                  {policyPreview.filename}
                </Title>
                <pre
                  style={{
                    marginTop: 8,
                    padding: 12,
                    background: '#1e1e1e',
                    color: '#d4d4d4',
                    borderRadius: 4,
                    overflow: 'auto',
                    maxHeight: 400,
                    fontSize: '0.8rem',
                  }}
                >
                  {policyPreview.content}
                </pre>
              </CardBody>
            </Card>
          ) : null}
        </StackItem>
      ) : null}

      {validation ? (
        <StackItem>
          <Accordion>
            <AccordionItem isExpanded={validationOpen}>
              <AccordionToggle
                id="results-validation-toggle"
                onClick={() => setValidationOpen((open) => !open)}
              >
                Validation against NSX intent
              </AccordionToggle>
              <AccordionContent id="results-validation-content">
                <Stack hasGutter>
                  <StackItem>
                    <Alert variant="warning" title="Work in progress" isInline>
                      This area is a work in progress.
                    </Alert>
                  </StackItem>
                  <StackItem>
                    <StatTiles
                      items={[
                        { label: 'Exact Matches', value: cmp.exact || 0, tone: 'green' },
                        { label: 'Missing', value: cmp.missing || 0, tone: 'red' },
                        { label: 'Additional', value: cmp.additional || 0, tone: 'orange' },
                        { label: 'Uncomparable', value: cmp.uncomparable || 0, tone: 'grey' },
                      ]}
                    />
                  </StackItem>
                  {findings.length ? (
                    <StackItem>
                      <Table aria-label="Comparison findings" variant="compact">
                        <Thead>
                          <Tr>
                            <Th>Category</Th>
                            <Th>Source</Th>
                            <Th>Destination</Th>
                            <Th>Protocol</Th>
                            <Th>Ports</Th>
                            <Th>Severity</Th>
                          </Tr>
                        </Thead>
                        <Tbody>
                          {findings.map((f, i) => (
                            <Tr key={`${displayFindingValue(f.category)}-${i}`}>
                              <Td>
                                <Label>{displayFindingValue(f.category)}</Label>
                              </Td>
                              <Td>{displayFindingValue(f.sourceIdentity)}</Td>
                              <Td>{displayFindingValue(f.destinationIdentity)}</Td>
                              <Td>{displayFindingValue(f.protocol)}</Td>
                              <Td>{displayFindingValue(f.portRange)}</Td>
                              <Td>{displayFindingValue(f.severity)}</Td>
                            </Tr>
                          ))}
                        </Tbody>
                      </Table>
                    </StackItem>
                  ) : (
                    <StackItem>
                      <DismissibleAlert variant="success" title="No differences found" isInline />
                    </StackItem>
                  )}
                  <StackItem>
                    <DismissibleAlert variant="info" title="Comparison note" isInline>
                      Comparison validates connectivity overlap, not semantic policy equivalence. Review
                      uncomparable items for known limitations.
                    </DismissibleAlert>
                  </StackItem>
                </Stack>
              </AccordionContent>
            </AccordionItem>
          </Accordion>
        </StackItem>
      ) : null}
    </Stack>
  );
}
