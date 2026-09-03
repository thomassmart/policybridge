import { useEffect, useState, type ComponentProps, type ReactNode } from 'react';
import { Alert, AlertActionCloseButton } from '@patternfly/react-core';

type AlertProps = ComponentProps<typeof Alert>;

export interface DismissibleAlertProps extends AlertProps {
  onDismiss?: () => void;
  dismissTitle?: string;
  /** When this value changes the alert becomes visible again. */
  resetKey?: string | number | null;
  /** Override the default close button (e.g. to add custom actions alongside dismiss). */
  actionClose?: ReactNode;
}

export function DismissibleAlert({
  onDismiss,
  dismissTitle = 'Dismiss',
  resetKey,
  actionClose,
  title,
  ...props
}: DismissibleAlertProps) {
  const [dismissed, setDismissed] = useState(false);

  useEffect(() => {
    setDismissed(false);
  }, [resetKey, title]);

  if (dismissed) return null;

  const handleClose = () => {
    setDismissed(true);
    onDismiss?.();
  };

  return (
    <Alert
      {...props}
      title={title}
      actionClose={
        actionClose ?? (
          <AlertActionCloseButton onClose={handleClose} title={dismissTitle} />
        )
      }
    />
  );
}
