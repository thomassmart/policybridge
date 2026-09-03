import { useEffect } from 'react';
import {
  Button,
  Skeleton,
  Stack,
  StackItem,
  TextInput,
  Title,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { useSession } from '@/context/SessionContext';
import type { LabelMapping, SegmentMapping } from '@/context/SessionContext';
import { downloadGet } from '@/api/client';
import { DismissibleAlert } from '@/components/DismissibleAlert';

function workloadLabels(labels: LabelMapping[]) {
  return labels.filter((e) => e.kind === 'vm');
}

export function MappingStep() {
  const { mapping, setMapping, loadMapping, saveMapping, sessionId, error, setError } = useSession();

  useEffect(() => {
    loadMapping().catch(() => {});
  }, [loadMapping]);

  const updateSegment = (index: number, patch: Partial<SegmentMapping>) => {
    if (!mapping) return;
    const segments = [...mapping.segments];
    segments[index] = { ...segments[index], ...patch };
    setMapping({ ...mapping, segments });
  };

  const updateLabel = (index: number, patch: Partial<LabelMapping>) => {
    if (!mapping) return;
    const labelMappings = [...(mapping.labelMappings || [])];
    labelMappings[index] = { ...labelMappings[index], ...patch };
    setMapping({ ...mapping, labelMappings });
  };

  const addLabel = (kind: LabelMapping['kind']) => {
    if (!mapping) return;
    setMapping({
      ...mapping,
      labelMappings: [
        ...(mapping.labelMappings || []),
        {
          nsxIdentity: '',
          kind,
          labelKey: kind === 'group' ? 'network.microseg/group' : 'app.kubernetes.io/name',
          labelValue: '',
        },
      ],
    });
  };

  const removeLabel = (index: number) => {
    if (!mapping) return;
    const labelMappings = [...(mapping.labelMappings || [])];
    labelMappings.splice(index, 1);
    setMapping({ ...mapping, labelMappings });
  };

  const downloadLabelPatch = async (format: 'sh' | 'json') => {
    if (!sessionId) return;
    await saveMapping();
    const q = format === 'json' ? '?format=json' : '';
    downloadGet(`/sessions/${sessionId}/export/label-patch${q}`, `label-patch.${format === 'json' ? 'json' : 'sh'}`);
  };

  if (!mapping) {
    return <Skeleton height="200px" />;
  }

  const segments = mapping.segments || [];
  const allLabels = mapping.labelMappings || [];
  const workloads = workloadLabels(allLabels);

  const renderLabelTable = (kind: LabelMapping['kind']) => {
    const indices = allLabels
      .map((e, i) => (e.kind === kind ? i : -1))
      .filter((i) => i >= 0);
    if (!indices.length) {
      return (
        <DismissibleAlert
          variant="info"
          title={
            kind === 'group'
              ? 'No groups referenced by the selected rules.'
              : 'No VMs in groups referenced by the selected rules.'
          }
          isInline
        />
      );
    }
    return (
      <Table aria-label={kind === 'group' ? 'Group label mapping' : 'Workload label patch'} variant="compact">
        <Thead>
          <Tr>
            <Th>{kind === 'group' ? 'NSX group' : 'Migrated workload name'}</Th>
            <Th>Label key</Th>
            <Th>Label value</Th>
            <Th />
          </Tr>
        </Thead>
        <Tbody>
          {indices.map((i) => {
            const entry = allLabels[i];
            return (
              <Tr key={`label-${i}`}>
                <Td>
                  <TextInput
                    aria-label="NSX identity"
                    value={entry.nsxIdentity}
                    onChange={(_e, v) => updateLabel(i, { nsxIdentity: v })}
                    placeholder={kind === 'group' ? 'grp-fleet-web' : 'fleet-web'}
                  />
                </Td>
                <Td>
                  <TextInput
                    aria-label="Label key"
                    value={entry.labelKey}
                    onChange={(_e, v) => updateLabel(i, { labelKey: v })}
                    placeholder={
                      kind === 'group' ? 'network.microseg/group' : 'app.kubernetes.io/name'
                    }
                  />
                </Td>
                <Td>
                  <TextInput
                    aria-label="Label value"
                    value={entry.labelValue}
                    onChange={(_e, v) => updateLabel(i, { labelValue: v })}
                    placeholder="workload-name"
                  />
                </Td>
                <Td>
                  <Button variant="danger" onClick={() => removeLabel(i)} aria-label="Remove mapping">
                    Remove
                  </Button>
                </Td>
              </Tr>
            );
          })}
        </Tbody>
      </Table>
    );
  };

  return (
    <Stack hasGutter>
      <StackItem>
        <Title headingLevel="h1" size="2xl">
          Mapping
        </Title>
        <p style={{ marginTop: 8, color: 'var(--pf-t--global--text--color--subtle)' }}>
          Map NSX segments to Kubernetes networking targets used by the selected DFW rules.
          Group labels shape generated policies; workload rows produce a label patch for VMs
          already migrated to the cluster.
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
        <Title headingLevel="h2" size="lg">
          Segment mapping
        </Title>
        {!segments.length ? (
          <DismissibleAlert
            variant="warning"
            title="No segments referenced by the selected rules."
            isInline
          />
        ) : (
          <Table aria-label="Segment mapping" variant="compact">
            <Thead>
              <Tr>
                <Th>NSX Segment</Th>
                <Th>Target</Th>
                <Th>Name</Th>
              </Tr>
            </Thead>
            <Tbody>
              {segments.map((seg, i) => (
                <Tr key={seg.segmentId}>
                  <Td>
                    <strong>{seg.segmentName}</strong>
                    <div style={{ fontSize: '0.75rem', color: 'var(--pf-t--global--text--color--subtle)' }}>
                      {seg.segmentId}
                    </div>
                  </Td>
                  <Td>
                    <select
                      value={seg.targetKind}
                      onChange={(e) =>
                        updateSegment(i, {
                          targetKind: e.target.value as SegmentMapping['targetKind'],
                        })
                      }
                    >
                      <option value="udn">UserDefinedNetwork</option>
                      <option value="nad">NetworkAttachmentDefinition</option>
                      <option value="pod-network">Pod network</option>
                    </select>
                  </Td>
                  <Td>
                    <TextInput
                      aria-label={`Target name for ${seg.segmentName}`}
                      value={seg.targetName || ''}
                      onChange={(_e, v) => updateSegment(i, { targetName: v })}
                      placeholder="resource name"
                    />
                  </Td>
                </Tr>
              ))}
            </Tbody>
          </Table>
        )}
      </StackItem>

      <StackItem>
        <Title headingLevel="h2" size="lg">
          Group label mapping
        </Title>
        <p style={{ fontSize: '0.85rem', color: 'var(--pf-t--global--text--color--subtle)', marginBottom: 12 }}>
          NSX groups used by the selected DFW rules, mapped to segmentation labels in generated
          network policies (not per-VM names).
        </p>
        {renderLabelTable('group')}
        <Button variant="secondary" onClick={() => addLabel('group')} style={{ marginTop: 12 }}>
          Add group mapping
        </Button>
      </StackItem>

      <StackItem>
        <Title headingLevel="h2" size="lg">
          Workload label patch
        </Title>
        <p style={{ fontSize: '0.85rem', color: 'var(--pf-t--global--text--color--subtle)', marginBottom: 12 }}>
          Match migrated workloads by their NSX VM name and download a script to apply labels with kubectl.
          These labels are not embedded in generated policies.
        </p>
        {renderLabelTable('vm')}
        <Stack hasGutter style={{ marginTop: 12 }}>
          <StackItem>
            <Button variant="secondary" onClick={() => addLabel('vm')}>
              Add workload mapping
            </Button>
          </StackItem>
          <StackItem>
            <Button variant="primary" onClick={() => downloadLabelPatch('sh')} isDisabled={!workloads.length}>
              Download label patch (shell)
            </Button>
            <Button
              variant="secondary"
              onClick={() => downloadLabelPatch('json')}
              isDisabled={!workloads.length}
              style={{ marginLeft: 8 }}
            >
              Download JSON
            </Button>
          </StackItem>
        </Stack>
      </StackItem>
    </Stack>
  );
}
