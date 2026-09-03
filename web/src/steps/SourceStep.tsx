import {
  Button,
  Card,
  CardBody,
  CardHeader,
  CardTitle,
  FileUpload,
  Form,
  FormGroup,
  Grid,
  GridItem,
  Stack,
  StackItem,
  TextInput,
  Title,
} from '@patternfly/react-core';
import { useSession } from '@/context/SessionContext';
import { JobProgress } from '@/components/JobProgress';
import { DismissibleAlert } from '@/components/DismissibleAlert';

export function SourceStep() {
  const {
    sourceType,
    setSourceType,
    connection,
    setConnection,
    testResult,
    testConnection,
    pendingUploadFile,
    setPendingUploadFile,
    uploadFileName,
    job,
    error,
    setError,
  } = useSession();

  return (
    <Stack hasGutter>
      <StackItem>
        <Title headingLevel="h1" size="2xl">
          Choose NSX Source
        </Title>
        <p style={{ marginTop: 8, color: 'var(--pf-t--global--text--color--subtle)' }}>
          Provide NSX configuration by connecting to NSX Manager or uploading a resource dump.
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
        <Grid hasGutter>
          <GridItem md={6}>
            <Card id="source-connect" isSelectable isSelected={sourceType === 'connect'} isFullHeight>
              <CardHeader
                selectableActions={{
                  variant: 'single',
                  name: 'nsx-source',
                  selectableActionId: 'source-connect-input',
                  selectableActionAriaLabelledby: 'source-connect',
                  isHidden: true,
                  onChange: () => setSourceType('connect'),
                }}
              >
                <CardTitle>Connect to NSX Manager</CardTitle>
              </CardHeader>
              <CardBody>
                Collect configuration via REST API. Credentials are held in memory only.
              </CardBody>
            </Card>
          </GridItem>
          <GridItem md={6}>
            <Card id="source-upload" isSelectable isSelected={sourceType === 'upload'} isFullHeight>
              <CardHeader
                selectableActions={{
                  variant: 'single',
                  name: 'nsx-source',
                  selectableActionId: 'source-upload-input',
                  selectableActionAriaLabelledby: 'source-upload',
                  isHidden: true,
                  onChange: () => setSourceType('upload'),
                }}
              >
                <CardTitle>Upload NSX Configuration</CardTitle>
              </CardHeader>
              <CardBody>
                Upload a JSON resource dump created with <code>nsxanalyzer collect</code>.
              </CardBody>
            </Card>
          </GridItem>
        </Grid>
      </StackItem>

      {sourceType === 'connect' ? (
        <StackItem>
          <DismissibleAlert variant="info" title="Collection can take several minutes" isInline>
            The upstream vmware-analyzer collector issues many NSX REST API calls. A small lab often
            finishes in 1–5 minutes, but larger environments can take longer. Use Test Connection
            first to confirm reachability.
          </DismissibleAlert>
          <Form style={{ marginTop: 16 }}>
            <FormGroup label="NSX Manager URL" isRequired fieldId="host">
              <TextInput
                id="host"
                type="url"
                placeholder="https://nsx-manager.example.com"
                value={connection.host}
                onChange={(_e, v) => setConnection({ host: v })}
              />
            </FormGroup>
            <FormGroup label="Username" isRequired fieldId="username">
              <TextInput
                id="username"
                autoComplete="username"
                value={connection.username}
                onChange={(_e, v) => setConnection({ username: v })}
              />
            </FormGroup>
            <FormGroup label="Password" isRequired fieldId="password">
              <TextInput
                id="password"
                type="password"
                autoComplete="current-password"
                placeholder={connection.passwordIsPlaceholder ? 'Password saved for this session' : ''}
                value={connection.password}
                onChange={(_e, v) =>
                  setConnection({ password: v, passwordIsPlaceholder: false })
                }
              />
            </FormGroup>
            <FormGroup fieldId="insecure">
              <label>
                <input
                  type="checkbox"
                  id="insecure"
                  checked={connection.insecureSkipVerify}
                  onChange={(e) => setConnection({ insecureSkipVerify: e.target.checked })}
                />{' '}
                Temporary insecure TLS exception (skip certificate verification)
              </label>
            </FormGroup>
            <Button variant="secondary" onClick={() => testConnection()}>
              Test Connection
            </Button>
            {testResult ? (
              <DismissibleAlert
                variant="success"
                title={testResult}
                isInline
                style={{ marginTop: 12 }}
                resetKey={testResult}
              />
            ) : null}
          </Form>
        </StackItem>
      ) : null}

      {sourceType === 'upload' ? (
        <StackItem>
          <Form>
            <FormGroup label="NSX Resource Dump (JSON)" fieldId="dump-file">
              <FileUpload
                id="dump-file"
                filename={uploadFileName || pendingUploadFile?.name || ''}
                filenamePlaceholder="Select a JSON resource dump"
                onFileInputChange={(_e, file) => setPendingUploadFile(file)}
                onClearClick={() => setPendingUploadFile(null)}
                browseButtonText="Browse"
              />
            </FormGroup>
          </Form>
        </StackItem>
      ) : null}

      <StackItem>
        <JobProgress job={job} />
      </StackItem>
    </Stack>
  );
}
