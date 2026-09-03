import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertActionLink,
  Checkbox,
  FormGroup,
  Skeleton,
  Stack,
  StackItem,
  Title,
} from '@patternfly/react-core';
import { Table, Tbody, Td, Th, Thead, Tr } from '@patternfly/react-table';
import { useSession } from '@/context/SessionContext';
import { DismissibleAlert } from '@/components/DismissibleAlert';
import { AnalysisFilterInput } from '@/components/AnalysisFilterInput';
import { buildAnalysisFilterSuggestions } from '@/utils/analysisFilterSuggestions';
import { filterRulesByText } from '@/utils/filterRulesByText';
import { parseConnectivity } from '@/utils/parseConnectivity';

export function RuleSelectionStep() {
  const {
    ruleSelection,
    loadRuleSelection,
    toggleRuleSelected,
    setAllRulesSelected,
    error,
    setError,
    analysis,
  } = useSession();
  const [filter, setFilter] = useState('');
  const [loadError, setLoadError] = useState<string | null>(null);

  const fetchRules = useCallback(async () => {
    setLoadError(null);
    try {
      await loadRuleSelection();
    } catch (e) {
      setLoadError(e instanceof Error ? e.message : String(e));
    }
  }, [loadRuleSelection]);

  useEffect(() => {
    if (ruleSelection) return;
    fetchRules();
  }, [fetchRules, ruleSelection]);

  const filteredRules = useMemo(
    () => filterRulesByText(ruleSelection?.rules || [], filter),
    [ruleSelection, filter],
  );

  const filterSuggestions = useMemo(
    () =>
      buildAnalysisFilterSuggestions(
        ruleSelection?.rules || [],
        parseConnectivity(analysis),
      ),
    [ruleSelection, analysis],
  );

  const selectedCount = ruleSelection?.selectedRuleIds.length ?? 0;
  const totalCount = ruleSelection?.rules.length ?? 0;
  const allFilteredSelected =
    filteredRules.length > 0 && filteredRules.every((r) => r.selected);
  const someFilteredSelected = filteredRules.some((r) => r.selected);

  if (!analysis) {
    return (
      <DismissibleAlert variant="warning" title="Run NSX analysis first" isInline />
    );
  }

  if (!ruleSelection) {
    if (loadError) {
      return (
        <DismissibleAlert
          variant="danger"
          title="Could not load DFW rules"
          isInline={false}
          resetKey={loadError}
          onDismiss={() => setLoadError(null)}
          actionLinks={
            <AlertActionLink onClick={() => fetchRules()}>Retry</AlertActionLink>
          }
        >
          {loadError}
        </DismissibleAlert>
      );
    }
    return <Skeleton height="240px" />;
  }

  return (
    <Stack hasGutter>
      <StackItem>
        <Title headingLevel="h1" size="2xl">
          Rule Selection
        </Title>
        <p style={{ marginTop: 8, color: 'var(--pf-t--global--text--color--subtle)' }}>
          Choose which DFW rules to include in policy generation. Deselect rules you do not want
          migrated to Kubernetes.
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
        <DismissibleAlert
          variant="info"
          title={`${selectedCount} of ${totalCount} rules selected`}
          isInline
          resetKey={`${selectedCount}-${totalCount}`}
        />
      </StackItem>

      <StackItem>
        <FormGroup label="Filter analysis" fieldId="rule-filter">
          <AnalysisFilterInput
            id="rule-filter"
            value={filter}
            onChange={setFilter}
            suggestions={filterSuggestions}
            aria-label="Filter DFW rules"
          />
        </FormGroup>
      </StackItem>

      <StackItem style={{ overflowX: 'auto' }}>
        <Table aria-label="DFW rule selection" variant="compact">
          <Thead>
            <Tr>
              <Th>
                <Checkbox
                  id="select-all-rules"
                  aria-label="Select all visible rules"
                  isChecked={allFilteredSelected ? true : someFilteredSelected ? null : false}
                  onChange={(_e, checked) =>
                    setAllRulesSelected(
                      filteredRules.map((r) => r.id ?? 0),
                      !!checked,
                    )
                  }
                />
              </Th>
              <Th>ID</Th>
              <Th>Name</Th>
              <Th>Category</Th>
              <Th>Policy</Th>
              <Th>Sources</Th>
              <Th>Destinations</Th>
              <Th>Services</Th>
              <Th>Action</Th>
            </Tr>
          </Thead>
          <Tbody>
            {filteredRules.map((rule) => (
              <Tr key={`${rule.id}-${rule.name}-${rule.policy}`}>
                <Td>
                  <Checkbox
                    id={`rule-${rule.id}-${rule.name}`}
                    aria-label={`Include rule ${rule.name}`}
                    isChecked={rule.selected}
                    onChange={(_e, checked) => toggleRuleSelected(rule.id ?? 0, !!checked)}
                  />
                </Td>
                <Td>{rule.id}</Td>
                <Td>{rule.name}</Td>
                <Td>{rule.category}</Td>
                <Td>{rule.policy}</Td>
                <Td>{(rule.sources || []).join(', ')}</Td>
                <Td>{(rule.destinations || []).join(', ')}</Td>
                <Td>{(rule.services || []).join(', ')}</Td>
                <Td>{rule.action}</Td>
              </Tr>
            ))}
          </Tbody>
        </Table>
        {!filteredRules.length ? (
          <DismissibleAlert variant="info" title="No rules match the current filter" isInline style={{ marginTop: 12 }} />
        ) : null}
      </StackItem>
    </Stack>
  );
}
