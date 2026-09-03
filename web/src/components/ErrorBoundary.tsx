import { Component, type ErrorInfo, type ReactNode } from 'react';
import { Button, Stack, StackItem, Title } from '@patternfly/react-core';

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  error: Error | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('PolicyBridge UI error', error, info.componentStack);
  }

  render() {
    if (this.state.error) {
      return (
        <Stack hasGutter style={{ padding: 24 }}>
          <StackItem>
            <Title headingLevel="h1" size="2xl">
              Something went wrong
            </Title>
          </StackItem>
          <StackItem>
            <p>{this.state.error.message}</p>
          </StackItem>
          <StackItem>
            <Button variant="primary" onClick={() => window.location.reload()}>
              Reload PolicyBridge
            </Button>
          </StackItem>
        </Stack>
      );
    }

    return this.props.children;
  }
}
