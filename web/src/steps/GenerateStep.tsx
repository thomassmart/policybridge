import { useEffect, useRef } from 'react';
import {
  Checkbox,
  ExpandableSection,
  Form,
  FormGroup,
  FormGroupLabelHelp,
  FormHelperText,
  HelperText,
  HelperTextItem,
  Popover,
  Skeleton,
  Stack,
  StackItem,
  TextInput,
  Title,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { useSession } from '@/context/SessionContext';
import type { SegmentMapping } from '@/context/SessionContext';
import { DismissibleAlert } from '@/components/DismissibleAlert';
import type { DFWRuleRow } from '@/api/types';

type NetworkingMode = 'udn' | 'pod-network';

function isAnyList(values?: string[]): boolean {
  if (!values || values.length === 0) return true;
  return values.every((v) => !v || v.toLowerCase() === 'any');
}

function defaultRuleLabel(rule: DFWRuleRow): string {
  const name = rule.name || `rule ${rule.id}`;
  const action = rule.action || 'ALLOW';
  const policy = rule.policy ? `${rule.policy} / ` : '';
  const catchAll =
    isAnyList(rule.sources) && isAnyList(rule.destinations) && isAnyList(rule.services)
      ? ' — ANY/ANY'
      : '';
  return `${policy}${name} (${action})${catchAll}`;
}

function networkingMode(segments: SegmentMapping[]): NetworkingMode {
  if (segments.length && segments.every((s) => s.targetKind === 'pod-network')) {
    return 'pod-network';
  }
  return 'udn';
}

function sharedTargetName(segments: SegmentMapping[]): string {
  if (!segments.length) return '';
  const first = (segments[0].targetName || '').trim();
  if (!first) return '';
  return segments.every((s) => (s.targetName || '').trim() === first) ? first : '';
}

function FieldLabelHelp({ ariaLabel, content }: { ariaLabel: string; content: string }) {
  const ref = useRef<HTMLButtonElement>(null);
  return (
    <Popover triggerRef={ref} bodyContent={content}>
      <FormGroupLabelHelp ref={ref} aria-label={ariaLabel} />
    </Popover>
  );
}

const HELP = {
  project:
    'OpenShift project where synthesised NetworkPolicies and UDNs are written. NSX segment names (Seg-Web, …) are not projects — use the real project (e.g. tom-testing). Applied to every segment unless you override rows below.',
  networking:
    'UserDefinedNetwork emits UDN manifests for OpenShift Virtualization / OVN primary UDN. Pod network targets the cluster default network.',
  endpoints:
    'Which endpoint objects are written into the synthesised manifests: VirtualMachines, Pod placeholders, or both.',
  defaultRule:
    'Last-resort ANY/ANY for traffic not matched by selected DFW rules. Prefer New - Drop for zero-trust.',
  adminPolicies:
    'Emit AdminNetworkPolicy for higher-priority NSX categories instead of flattening everything to allow-only NetworkPolicies. Needs the AdminNetworkPolicy CRD.',
  dnsPolicy:
    'Add egress so workloads can reach cluster DNS (UDP/53). Enable under default-deny if name resolution would otherwise be blocked.',
  hintsInference:
    'Infer NSX groups that share no VMs in this snapshot to simplify policy flattening. Membership can change after the dump.',
  vmFilter: 'Optional: limit synthesis to these NSX VM names (comma-separated). Leave empty for all in scope.',
} as const;

export function GenerateStep() {
  const {
    mapping,
    setMapping,
    loadMapping,
    generation,
    setGeneration,
    ruleSelection,
    loadRuleSelection,
    error,
    setError,
  } = useSession();

  useEffect(() => {
    loadMapping().catch(() => {});
  }, [loadMapping]);

  useEffect(() => {
    if (ruleSelection) return;
    loadRuleSelection().catch(() => {});
  }, [loadRuleSelection, ruleSelection]);

  if (!mapping) {
    return <Skeleton height="200px" />;
  }

  const segments = mapping.segments || [];
  const mode = networkingMode(segments);
  const project = sharedTargetName(segments);

  const setNetworkingMode = (next: NetworkingMode) => {
    setMapping({
      ...mapping,
      segments: segments.map((s) => ({ ...s, targetKind: next })),
    });
  };

  const setProjectForAll = (ns: string) => {
    setMapping({
      ...mapping,
      segments: segments.map((s) => ({ ...s, targetName: ns })),
    });
  };

  const updateSegment = (index: number, patch: Partial<SegmentMapping>) => {
    const next = [...segments];
    next[index] = { ...next[index], ...patch };
    setMapping({ ...mapping, segments: next });
  };

  return (
    <Stack hasGutter>
      <StackItem>
        <Title headingLevel="h1" size="2xl">
          Generate
        </Title>
        <p style={{ marginTop: 8, color: 'var(--pf-t--global--text--color--subtle)' }}>
          Choose where policies land in OpenShift and how they are synthesised from the selected
          NSX rules.
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
          Target
        </Title>
        <Form>
          <FormGroup
            label="OpenShift project"
            fieldId="target-project"
            labelHelp={<FieldLabelHelp ariaLabel="More info for OpenShift project" content={HELP.project} />}
          >
            <TextInput
              id="target-project"
              value={project}
              isDisabled={!segments.length}
              placeholder="e.g. tom-testing"
              onChange={(_e, v) => setProjectForAll(v)}
              aria-describedby="target-project-helper"
            />
            <FormHelperText>
              <HelperText>
                <HelperTextItem id="target-project-helper">
                  {segments.length
                    ? `Sets the target namespace for all ${segments.length} NSX segment(s) in scope. Override individual rows below if segments map to different projects.`
                    : 'No segments in scope for the selected rules.'}
                </HelperTextItem>
              </HelperText>
            </FormHelperText>
          </FormGroup>

          <FormGroup
            label="Networking"
            fieldId="networking-mode"
            labelHelp={<FieldLabelHelp ariaLabel="More info for Networking" content={HELP.networking} />}
          >
            <select
              id="networking-mode"
              value={mode}
              disabled={!segments.length}
              onChange={(e) => setNetworkingMode(e.target.value as NetworkingMode)}
            >
              <option value="udn">UserDefinedNetwork</option>
              <option value="pod-network">Pod network</option>
            </select>
          </FormGroup>
        </Form>
      </StackItem>

      {segments.length ? (
        <StackItem>
          <ExpandableSection toggleText={`NSX segments (${segments.length})`} isIndented>
            <Table aria-label="Segment target namespaces" variant="compact">
              <Thead>
                <Tr>
                  <Th>NSX segment</Th>
                  <Th>Target namespace</Th>
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
                      <TextInput
                        aria-label={`Target namespace for ${seg.segmentName}`}
                        value={seg.targetName || ''}
                        onChange={(_e, v) => updateSegment(i, { targetName: v })}
                        placeholder="kubernetes-namespace"
                      />
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          </ExpandableSection>
        </StackItem>
      ) : (
        <StackItem>
          <DismissibleAlert
            variant="warning"
            title="No segments referenced by the selected rules."
            isInline
          />
        </StackItem>
      )}

      <StackItem>
        <Title headingLevel="h2" size="lg">
          Synthesis
        </Title>
        <Form>
          <FormGroup
            label="Endpoints"
            fieldId="endpoints"
            labelHelp={<FieldLabelHelp ariaLabel="More info for Endpoints" content={HELP.endpoints} />}
          >
            <select
              id="endpoints"
              value={generation.endpointsMapping}
              onChange={(e) =>
                setGeneration({
                  endpointsMapping: e.target.value as 'vms' | 'pods' | 'both',
                })
              }
            >
              <option value="both">VirtualMachines and Pods</option>
              <option value="vms">VirtualMachines only</option>
              <option value="pods">Pods only</option>
            </select>
          </FormGroup>

          <FormGroup
            label="Default rule"
            fieldId="default-rule"
            labelHelp={
              <FieldLabelHelp ariaLabel="More info for Default rule" content={HELP.defaultRule} />
            }
          >
            <select
              id="default-rule"
              value={generation.defaultRule || 'new-drop'}
              onChange={(e) => setGeneration({ defaultRule: e.target.value })}
            >
              <optgroup label="New">
                <option value="new-drop">New — Drop (recommended)</option>
                <option value="new-allow">New — Allow</option>
              </optgroup>
              <optgroup label="Existing rules">
                {(ruleSelection?.rules || [])
                  .filter((rule) => rule.id != null)
                  .map((rule) => (
                    <option key={rule.id} value={String(rule.id)}>
                      {defaultRuleLabel(rule)}
                    </option>
                  ))}
              </optgroup>
            </select>
          </FormGroup>
        </Form>
      </StackItem>

      <StackItem>
        <ExpandableSection toggleText="Advanced options" isIndented>
          <Form>
            <FormGroup fieldId="admin-policies">
              <Checkbox
                id="admin-policies"
                label={
                  <>
                    Generate AdminNetworkPolicy resources{' '}
                    <FieldLabelHelp
                      ariaLabel="More info for AdminNetworkPolicy"
                      content={HELP.adminPolicies}
                    />
                  </>
                }
                isChecked={!!generation.synthesizeAdminPolicies}
                onChange={(_e, checked) => setGeneration({ synthesizeAdminPolicies: checked })}
              />
            </FormGroup>
            <FormGroup fieldId="dns-policy">
              <Checkbox
                id="dns-policy"
                label={
                  <>
                    Generate DNS access policy{' '}
                    <FieldLabelHelp ariaLabel="More info for DNS policy" content={HELP.dnsPolicy} />
                  </>
                }
                isChecked={!!generation.createDNSPolicy}
                onChange={(_e, checked) => setGeneration({ createDNSPolicy: checked })}
              />
            </FormGroup>
            <FormGroup fieldId="hints-inference">
              <Checkbox
                id="hints-inference"
                label={
                  <>
                    Infer disjoint groups/tags{' '}
                    <FieldLabelHelp
                      ariaLabel="More info for hints inference"
                      content={HELP.hintsInference}
                    />
                  </>
                }
                isChecked={!!generation.hintsInference}
                onChange={(_e, checked) => setGeneration({ hintsInference: checked })}
              />
            </FormGroup>
            <FormGroup
              label="VM output filter"
              fieldId="vm-filter"
              labelHelp={<FieldLabelHelp ariaLabel="More info for VM filter" content={HELP.vmFilter} />}
            >
              <TextInput
                id="vm-filter"
                placeholder="vm1, vm2"
                value={(generation.outputFilter || []).join(', ')}
                onChange={(_e, v) =>
                  setGeneration({
                    outputFilter: v
                      .split(',')
                      .map((s) => s.trim())
                      .filter(Boolean),
                  })
                }
              />
            </FormGroup>
          </Form>
        </ExpandableSection>
      </StackItem>
    </Stack>
  );
}
