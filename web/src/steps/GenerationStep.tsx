import { useEffect } from 'react';
import {
  Checkbox,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Form,
  FormGroup,
  FormHelperText,
  HelperText,
  HelperTextItem,
  Stack,
  StackItem,
  TextInput,
  Title,
} from '@patternfly/react-core';
import { useSession } from '@/context/SessionContext';
import { DismissibleAlert } from '@/components/DismissibleAlert';
import type { DFWRuleRow } from '@/api/types';

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

export function GenerationStep() {
  const {
    generation,
    setGeneration,
    mapping,
    error,
    setError,
    ruleSelection,
    loadRuleSelection,
  } = useSession();

  useEffect(() => {
    if (ruleSelection) return;
    loadRuleSelection().catch(() => {});
  }, [loadRuleSelection, ruleSelection]);

  const segments = mapping?.segments || [];
  const labels = mapping?.labelMappings || [];
  const groupLabels = labels.filter((l) => l.kind === 'group');
  const workloadPatches = labels.filter((l) => l.kind === 'vm');
  const counts = { udn: 0, nad: 0, 'pod-network': 0 };
  segments.forEach((s) => {
    counts[s.targetKind] = (counts[s.targetKind] || 0) + 1;
  });

  return (
    <Stack hasGutter>
      <StackItem>
        <Title headingLevel="h1" size="2xl">
          Generation Settings
        </Title>
        <p style={{ marginTop: 8, color: 'var(--pf-t--global--text--color--subtle)' }}>
          Configure how Kubernetes network policies are synthesised from NSX intent.
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
        <DismissibleAlert variant="info" title="Defaults" isInline>
          Segment and label mappings were configured in the previous step. Policy optimisation uses
          upstream vmware-analyzer defaults in the pinned release.
        </DismissibleAlert>
      </StackItem>

      <StackItem>
        <Form>
          <FormGroup label="Target Endpoint Mapping" fieldId="endpoints">
            <select
              id="endpoints"
              value={generation.endpointsMapping}
              onChange={(e) =>
                setGeneration({
                  endpointsMapping: e.target.value as 'vms' | 'pods' | 'both',
                })
              }
            >
              <option value="both">VMs and Pods</option>
              <option value="vms">VMs only</option>
              <option value="pods">Pods only</option>
            </select>
          </FormGroup>

          <FormGroup label="Mapping summary">
            <DescriptionList isHorizontal>
              <DescriptionListGroup>
                <DescriptionListTerm>Segments</DescriptionListTerm>
                <DescriptionListDescription>
                  {segments.length
                    ? `${segments.length} segment(s): ${counts.udn ? `${counts.udn} UDN` : ''}${counts.nad ? ` · ${counts.nad} NAD` : ''}${counts['pod-network'] ? ` · ${counts['pod-network']} pod network` : ''}`
                    : 'No segment mappings'}
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Group labels</DescriptionListTerm>
                <DescriptionListDescription>
                  {groupLabels.length
                    ? `${groupLabels.length} group label mapping(s) for policy synthesis`
                    : 'None'}
                </DescriptionListDescription>
              </DescriptionListGroup>
              <DescriptionListGroup>
                <DescriptionListTerm>Workload patches</DescriptionListTerm>
                <DescriptionListDescription>
                  {workloadPatches.length
                    ? `${workloadPatches.length} workload patch row(s) (export from Mapping step)`
                    : 'None'}
                </DescriptionListDescription>
              </DescriptionListGroup>
            </DescriptionList>
          </FormGroup>

          <FormGroup label="Default rule" fieldId="default-rule">
            <select
              id="default-rule"
              aria-describedby="default-rule-helper"
              value={generation.defaultRule || 'new-drop'}
              onChange={(e) => setGeneration({ defaultRule: e.target.value })}
            >
              <optgroup label="New">
                <option value="new-drop">New - Drop</option>
                <option value="new-allow">New - Allow</option>
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
            <FormHelperText>
              <HelperText>
                <HelperTextItem id="default-rule-helper">
                  Last-resort ANY/ANY decision for traffic not matched by the selected DFW rules.
                  Prefer a default-deny or default-allow when choosing an existing rule.
                </HelperTextItem>
              </HelperText>
            </FormHelperText>
          </FormGroup>

          <FormGroup label="Policy Optimisation Level" fieldId="optimisation">
            <select id="optimisation" disabled title="Not available in vmware-analyzer v0.2.1">
              <option value="max">Maximum (pinned release default)</option>
            </select>
          </FormGroup>

          <FormGroup fieldId="admin-policies">
            <Checkbox
              id="admin-policies"
              label="Generate AdminNetworkPolicy resources"
              isChecked={!!generation.synthesizeAdminPolicies}
              onChange={(_e, checked) => setGeneration({ synthesizeAdminPolicies: checked })}
            />
          </FormGroup>
          <FormGroup fieldId="dns-policy">
            <Checkbox
              id="dns-policy"
              label="Generate DNS access policy"
              isChecked={!!generation.createDNSPolicy}
              onChange={(_e, checked) => setGeneration({ createDNSPolicy: checked })}
            />
          </FormGroup>
          <FormGroup fieldId="hints-inference">
            <Checkbox
              id="hints-inference"
              label="Automatic disjoint group/tag inference"
              isChecked={!!generation.hintsInference}
              onChange={(_e, checked) => setGeneration({ hintsInference: checked })}
            />
          </FormGroup>
          <FormGroup label="VM Output Filter (comma-separated)" fieldId="vm-filter">
            <TextInput
              id="vm-filter"
              placeholder="vm1, vm2"
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
      </StackItem>
    </Stack>
  );
}
