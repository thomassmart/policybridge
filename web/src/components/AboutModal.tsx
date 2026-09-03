import {
  AboutModal as PFAboutModal,
  Content,
  ContentVariants,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
} from '@patternfly/react-core';
import type { AboutInfo } from '@/api/types';

interface AboutModalProps {
  isOpen: boolean;
  onClose: () => void;
  about: AboutInfo | null;
  sessionId: string | null;
}

export function AboutModal({ isOpen, onClose, about, sessionId }: AboutModalProps) {
  return (
    <PFAboutModal
      isOpen={isOpen}
      onClose={onClose}
      productName="PolicyBridge"
      brandImageSrc=""
      brandImageAlt="PolicyBridge"
      trademark="PolicyBridge is an independent project and is not endorsed by NP-Guard, VMware, Broadcom, Red Hat, or IBM."
    >
      <Content component={ContentVariants.p}>
        NSX to Kubernetes microsegmentation conversion.
      </Content>
      <DescriptionList>
        <DescriptionListGroup>
          <DescriptionListTerm>Version</DescriptionListTerm>
          <DescriptionListDescription>{about?.version || '0.1.0'}</DescriptionListDescription>
        </DescriptionListGroup>
        <DescriptionListGroup>
          <DescriptionListTerm>vmware-analyzer</DescriptionListTerm>
          <DescriptionListDescription>{about?.vmwareAnalyzer || '—'}</DescriptionListDescription>
        </DescriptionListGroup>
        <DescriptionListGroup>
          <DescriptionListTerm>netpol-analyzer</DescriptionListTerm>
          <DescriptionListDescription>{about?.netpolAnalyzer || '—'}</DescriptionListDescription>
        </DescriptionListGroup>
        {sessionId ? (
          <DescriptionListGroup>
            <DescriptionListTerm>Session ID</DescriptionListTerm>
            <DescriptionListDescription>
              <code>{sessionId}</code>
            </DescriptionListDescription>
          </DescriptionListGroup>
        ) : null}
      </DescriptionList>
    </PFAboutModal>
  );
}
