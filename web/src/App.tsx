import { useState } from 'react';
import { Page, PageSection, Wizard, WizardStep } from '@patternfly/react-core';
import { AppMasthead } from '@/components/AppMasthead';
import { AboutModal } from '@/components/AboutModal';
import { WizardFooterActions } from '@/components/WizardFooterActions';
import { SessionProvider, useSession } from '@/context/SessionContext';
import { SourceStep } from '@/steps/SourceStep';
import { IntentStep } from '@/steps/IntentStep';
import { MappingStep } from '@/steps/MappingStep';
import { RuleSelectionStep } from '@/steps/RuleSelectionStep';
import { GenerationStep } from '@/steps/GenerationStep';
import { ResultsStep } from '@/steps/ResultsStep';
import { ExportStep } from '@/steps/ExportStep';

function PolicyBridgeWizard() {
  const { about, sessionId, initSession } = useSession();
  const [aboutOpen, setAboutOpen] = useState(false);

  return (
    <>
      <Page isContentFilled masthead={<AppMasthead onAbout={() => setAboutOpen(true)} onNewAnalysis={() => initSession()} />}>
        <PageSection
          type="wizard"
          isFilled
          hasBodyWrapper={false}
          padding={{ default: 'noPadding' }}
          className="pb-wizard-section"
        >
          <Wizard
            className="pb-wizard"
            height="100%"
            navAriaLabel="PolicyBridge analysis steps"
            footer={<WizardFooterActions />}
          >
            <WizardStep name="Source" id="source">
              <SourceStep />
            </WizardStep>
            <WizardStep name="NSX intent" id="intent">
              <IntentStep />
            </WizardStep>
            <WizardStep name="Rule selection" id="rules">
              <RuleSelectionStep />
            </WizardStep>
            <WizardStep name="Mapping" id="mapping">
              <MappingStep />
            </WizardStep>
            <WizardStep name="Generation settings" id="generation">
              <GenerationStep />
            </WizardStep>
            <WizardStep name="Results" id="results">
              <ResultsStep />
            </WizardStep>
            <WizardStep name="Export" id="export">
              <ExportStep />
            </WizardStep>
          </Wizard>
        </PageSection>
      </Page>
      <AboutModal
        isOpen={aboutOpen}
        onClose={() => setAboutOpen(false)}
        about={about}
        sessionId={sessionId}
      />
    </>
  );
}

export function App() {
  return (
    <SessionProvider>
      <PolicyBridgeWizard />
    </SessionProvider>
  );
}
