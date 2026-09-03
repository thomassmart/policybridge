import {
  Button,
  Masthead,
  MastheadBrand,
  MastheadContent,
  MastheadMain,
} from '@patternfly/react-core';

interface AppMastheadProps {
  onAbout: () => void;
  onNewAnalysis: () => void;
}

export function AppMasthead({ onAbout, onNewAnalysis }: AppMastheadProps) {
  return (
    <Masthead className="pb-masthead">
      <MastheadMain>
        <MastheadBrand className="pb-masthead__brand">
          <span className="pb-masthead__title">
            Policy<span className="pb-masthead__accent">Bridge</span>
          </span>
          <span className="pb-masthead__tagline">NSX to Kubernetes microsegmentation</span>
        </MastheadBrand>
      </MastheadMain>
      <MastheadContent className="pb-masthead__content">
        <div className="pb-masthead__actions">
          <Button variant="secondary" onClick={onNewAnalysis}>
            New analysis
          </Button>
          <Button variant="link" onClick={onAbout} className="pb-masthead__about">
            About
          </Button>
        </div>
      </MastheadContent>
    </Masthead>
  );
}
