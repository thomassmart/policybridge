import { useState } from 'react';
import {
  ActionList,
  ActionListGroup,
  ActionListItem,
  Button,
  useWizardContext,
  WizardFooterWrapper,
} from '@patternfly/react-core';
import { useSession } from '@/context/SessionContext';
import { downloadGet } from '@/api/client';

export function WizardFooterActions() {
  const { activeStep, goToNextStep, goToPrevStep } = useWizardContext();
  const session = useSession();
  const [busy, setBusy] = useState(false);

  const stepId = activeStep?.id != null ? String(activeStep.id) : '';
  const isExport = stepId === 'export';
  const isIntent = stepId === 'intent';
  const isRules = stepId === 'rules';
  const isResults = stepId === 'results';

  const intentBlocked = isIntent && (session.analysisStarted && !session.analysis);
  const rulesBlocked = isRules && (!session.ruleSelection || !session.ruleSelection.selectedRuleIds.length);
  const resultsBlocked = isResults && (session.job.running || (!session.validation && !session.error));

  const nextDisabled =
    busy ||
    intentBlocked ||
    rulesBlocked ||
    resultsBlocked ||
    (isIntent && session.job.running);

  const nextLabel =
    stepId === 'source'
      ? 'Continue'
      : stepId === 'generate'
        ? 'Generate and validate'
        : 'Next';

  const handleNext = async () => {
    setBusy(true);
    session.setError(null);
    try {
      switch (stepId) {
        case 'source': {
          const ok = await session.submitSource();
          if (!ok) return;
          goToNextStep();
          break;
        }
        case 'intent':
          goToNextStep();
          break;
        case 'rules':
          await session.saveRuleSelection();
          goToNextStep();
          break;
        case 'generate':
          await session.saveMapping();
          session.invalidateGenerated();
          goToNextStep();
          break;
        case 'results':
          goToNextStep();
          break;
        default:
          break;
      }
    } catch (e) {
      session.setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const handleBack = () => {
    if (stepId === 'results') {
      session.invalidateGenerated();
    }
    goToPrevStep();
  };

  return (
    <WizardFooterWrapper>
      <ActionList className="pb-wizard-footer">
        <ActionListGroup>
          {!isExport ? (
            <>
              {isIntent && session.sessionId && session.analysis ? (
                <ActionListItem>
                  <Button
                    variant="secondary"
                    onClick={() =>
                      downloadGet(
                        `/sessions/${session.sessionId}/export/dump`,
                        'nsx-resources.json',
                      )
                    }
                  >
                    Download NSX configuration (JSON)
                  </Button>
                </ActionListItem>
              ) : null}
              <ActionListItem>
                <Button
                  variant="secondary"
                  onClick={handleBack}
                  isDisabled={busy || !activeStep || activeStep.index === 1}
                >
                  Back
                </Button>
              </ActionListItem>
              <ActionListItem>
                <Button
                  variant="primary"
                  onClick={() => handleNext()}
                  isLoading={busy}
                  isDisabled={nextDisabled}
                >
                  {nextLabel}
                </Button>
              </ActionListItem>
            </>
          ) : (
            <ActionListItem>
              <Button variant="secondary" onClick={handleBack}>
                Back
              </Button>
            </ActionListItem>
          )}
        </ActionListGroup>
      </ActionList>
    </WizardFooterWrapper>
  );
}
