import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import { api, apiUpload } from '@/api/client';
import { runJob } from '@/api/jobs';
import type {
  AboutInfo,
  AnalysisResult,
  ConnectPayload,
  ConnectionView,
  GenerationConfig,
  JobState,
  LabelMapping,
  MappingConfig,
  PoliciesResult,
  PolicyPreview,
  SegmentMapping,
  SourceType,
  Summary,
  ValidationResult,
  RuleSelectionView,
} from '@/api/types';

interface ConnectionForm {
  host: string;
  username: string;
  password: string;
  insecureSkipVerify: boolean;
  configured: boolean;
  passwordIsPlaceholder: boolean;
}

const defaultConnection = (): ConnectionForm => ({
  host: '',
  username: '',
  password: '',
  insecureSkipVerify: false,
  configured: false,
  passwordIsPlaceholder: false,
});

const defaultGeneration = (): GenerationConfig => ({
  endpointsMapping: 'both',
  segmentsMapping: 'udns',
  policyOptimizationLevel: 'max',
  synthesizeAdminPolicies: false,
  createDNSPolicy: false,
  hintsInference: false,
  defaultRule: 'new-drop',
});

const emptyJob = (): JobState => ({
  label: '',
  running: false,
  progress: 0,
  message: '',
  logs: [],
  error: undefined,
});

interface SessionContextValue {
  sessionId: string | null;
  about: AboutInfo | null;
  error: string | null;
  setError: (msg: string | null) => void;
  sourceType: SourceType | null;
  setSourceType: (t: SourceType | null) => void;
  connection: ConnectionForm;
  setConnection: (patch: Partial<ConnectionForm>) => void;
  testResult: string | null;
  summary: Summary | null;
  analysis: AnalysisResult | null;
  analysisStarted: boolean;
  ruleSelection: RuleSelectionView | null;
  mapping: MappingConfig | null;
  setMapping: (m: MappingConfig | null) => void;
  generation: GenerationConfig;
  setGeneration: (patch: Partial<GenerationConfig>) => void;
  policies: PoliciesResult | null;
  policyPreview: PolicyPreview | null;
  validation: ValidationResult | null;
  pendingUploadFile: File | null;
  setPendingUploadFile: (f: File | null) => void;
  uploadFileName: string | null;
  job: JobState;
  initSession: () => Promise<void>;
  testConnection: () => Promise<void>;
  submitSource: () => Promise<boolean>;
  ensureAnalysis: () => Promise<void>;
  loadRuleSelection: () => Promise<void>;
  saveRuleSelection: () => Promise<void>;
  toggleRuleSelected: (ruleId: number, selected: boolean) => void;
  setAllRulesSelected: (ruleIds: number[], selected: boolean) => void;
  loadMapping: () => Promise<void>;
  saveMapping: () => Promise<void>;
  runGenerateAndValidate: () => Promise<void>;
  loadPolicyFile: (filename: string) => Promise<void>;
  invalidateGenerated: () => void;
  connectionPayload: () => ConnectPayload;
}

const SessionContext = createContext<SessionContextValue | null>(null);

function deriveSegmentsMapping(segments: SegmentMapping[]): 'pod-network' | 'udns' {
  if (!segments.length) return 'udns';
  if (segments.every((s) => s.targetKind === 'pod-network')) return 'pod-network';
  return 'udns';
}

export function SessionProvider({ children }: { children: ReactNode }) {
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [about, setAbout] = useState<AboutInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sourceType, setSourceType] = useState<SourceType | null>(null);
  const [connection, setConnectionState] = useState<ConnectionForm>(defaultConnection());
  const [testResult, setTestResult] = useState<string | null>(null);
  const [summary, setSummary] = useState<Summary | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [analysisStarted, setAnalysisStarted] = useState(false);
  const [ruleSelection, setRuleSelection] = useState<RuleSelectionView | null>(null);
  const [mapping, setMapping] = useState<MappingConfig | null>(null);
  const [generation, setGenerationState] = useState<GenerationConfig>(defaultGeneration());
  const [policies, setPolicies] = useState<PoliciesResult | null>(null);
  const [policyPreview, setPolicyPreview] = useState<PolicyPreview | null>(null);
  const [validation, setValidation] = useState<ValidationResult | null>(null);
  const [pendingUploadFile, setPendingUploadFile] = useState<File | null>(null);
  const [uploadFileName, setUploadFileName] = useState<string | null>(null);
  const [job, setJob] = useState<JobState>(emptyJob());

  const setConnection = useCallback((patch: Partial<ConnectionForm>) => {
    setConnectionState((prev) => ({ ...prev, ...patch }));
  }, []);

  const setGeneration = useCallback((patch: Partial<GenerationConfig>) => {
    setGenerationState((prev) => ({ ...prev, ...patch }));
  }, []);

  const connectionPayload = useCallback((): ConnectPayload => {
    const payload: ConnectPayload = {
      host: connection.host,
      username: connection.username,
      insecureSkipVerify: connection.insecureSkipVerify,
    };
    if (!connection.passwordIsPlaceholder && connection.password) {
      payload.password = connection.password;
    }
    return payload;
  }, [connection]);

  const applyConnectionView = useCallback((view: ConnectionView) => {
    if (!view?.configured) return;
    setConnectionState((prev) => ({
      ...prev,
      host: view.host || '',
      username: view.username || '',
      insecureSkipVerify: !!view.insecureSkipVerify,
      configured: true,
      passwordIsPlaceholder: view.hasPassword ? true : prev.passwordIsPlaceholder,
      password: view.hasPassword && !prev.password ? '' : prev.password,
    }));
  }, []);

  const resetWorkflow = useCallback(() => {
    setSourceType(null);
    setConnectionState(defaultConnection());
    setTestResult(null);
    setSummary(null);
    setAnalysis(null);
    setAnalysisStarted(false);
    setRuleSelection(null);
    setMapping(null);
    setGenerationState(defaultGeneration());
    setPolicies(null);
    setPolicyPreview(null);
    setValidation(null);
    setPendingUploadFile(null);
    setUploadFileName(null);
    setJob(emptyJob());
    setError(null);
  }, []);

  const initSession = useCallback(async () => {
    resetWorkflow();
    const { id } = await api<{ id: string }>('POST', '/sessions', {});
    setSessionId(id);
    try {
      const conn = await api<ConnectionView>('GET', `/sessions/${id}/source/connection`);
      applyConnectionView(conn);
      if (conn.configured) setSourceType('connect');
    } catch {
      /* no connection yet */
    }
  }, [applyConnectionView, resetWorkflow]);

  useEffect(() => {
    api<AboutInfo>('GET', '/about').then(setAbout).catch(() => {});
    initSession().catch((e: Error) => setError(e.message));
  }, [initSession]);

  const updateJob = useCallback((patch: Partial<JobState>) => {
    setJob((prev) => ({ ...prev, ...patch }));
  }, []);

  const testConnection = useCallback(async () => {
    if (!sessionId) return;
    setError(null);
    if (!connection.host.trim()) {
      setError('NSX Manager URL is required');
      return;
    }
    if (!connection.username.trim()) {
      setError('Username is required');
      return;
    }
    if (!connection.configured && !connection.password.trim()) {
      setError('Password is required');
      return;
    }
    try {
      const result = await api<{ message: string; connection?: ConnectionView }>(
        'POST',
        `/sessions/${sessionId}/source/test`,
        connectionPayload(),
      );
      setTestResult(result.message);
      if (result.connection) applyConnectionView(result.connection);
      setConnection({ configured: true, passwordIsPlaceholder: true, password: '' });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [sessionId, connection, connectionPayload, applyConnectionView, setConnection]);

  const submitSource = useCallback(async (): Promise<boolean> => {
    if (!sessionId) return false;
    setError(null);
    if (!sourceType) {
      setError('Select a source type');
      return false;
    }

    if (sourceType === 'upload') {
      const file = pendingUploadFile;
      if (!file) {
        setError('Select a JSON file before continuing');
        return false;
      }
      setUploadFileName(file.name);
      updateJob({ label: 'Upload', running: true, progress: 0, message: 'Uploading…', logs: [] });
      try {
        const text = await file.text();
        const s = await apiUpload<Summary>(`/sessions/${sessionId}/source/upload`, text);
        setSummary(s);
        setPendingUploadFile(null);
        updateJob({ running: false, progress: 100, message: `Uploaded ${file.name}`, logs: [`Uploaded ${file.name}`] });
        return true;
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        setError(msg);
        updateJob({ running: false, message: msg, error: msg });
        return false;
      }
    }

    if (!connection.host.trim()) {
      setError('NSX Manager URL is required');
      return false;
    }
    if (!connection.username.trim()) {
      setError('Username is required');
      return false;
    }
    if (!connection.configured && !connection.password.trim()) {
      setError('Password is required');
      return false;
    }

    try {
      const jobResult = await runJob(
        sessionId,
        `/sessions/${sessionId}/source/connect`,
        connectionPayload(),
        'NSX collection',
        updateJob,
      );
      if (jobResult.state === 'failed') {
        setError(jobResult.error || 'Collection failed');
        return false;
      }
      const conn = await api<ConnectionView>('GET', `/sessions/${sessionId}/source/connection`);
      applyConnectionView(conn);
      setConnection({ configured: true, passwordIsPlaceholder: true, password: '' });
      const s = await api<Summary>('GET', `/sessions/${sessionId}/summary`);
      setSummary(s);
      return true;
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return false;
    }
  }, [
    sessionId,
    sourceType,
    pendingUploadFile,
    connection,
    connectionPayload,
    applyConnectionView,
    setConnection,
    updateJob,
  ]);

  const ensureAnalysis = useCallback(async () => {
    if (!sessionId || analysis || analysisStarted) return;
    setAnalysisStarted(true);
    setError(null);
    try {
      const jobResult = await runJob(
        sessionId,
        `/sessions/${sessionId}/analyze`,
        {},
        'NSX analysis',
        updateJob,
      );
      if (jobResult.state === 'failed') {
        setError(jobResult.error || 'Analysis failed');
        setAnalysisStarted(false);
        return;
      }
      const result = await api<AnalysisResult>('GET', `/sessions/${sessionId}/analysis`);
      setAnalysis(result);
      try {
        const rules = await api<RuleSelectionView>('GET', `/sessions/${sessionId}/rules/selection`);
        setRuleSelection(rules);
      } catch {
        // Rule selection is loaded again on the rules step; analysis can still be reviewed.
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setAnalysisStarted(false);
    }
  }, [sessionId, analysis, analysisStarted, updateJob]);

  const invalidateGenerated = useCallback(() => {
    setPolicies(null);
    setPolicyPreview(null);
    setValidation(null);
  }, []);

  const loadRuleSelection = useCallback(async () => {
    if (!sessionId) return;
    const view = await api<RuleSelectionView>('GET', `/sessions/${sessionId}/rules/selection`);
    setRuleSelection(view);
  }, [sessionId]);

  const saveRuleSelection = useCallback(async () => {
    if (!sessionId || !ruleSelection) return;
    if (!ruleSelection.selectedRuleIds.length) {
      throw new Error('Select at least one DFW rule');
    }
    const saved = await api<RuleSelectionView>('PUT', `/sessions/${sessionId}/rules/selection`, {
      selectedRuleIds: ruleSelection.selectedRuleIds,
    });
    setRuleSelection(saved);
    setMapping(null);
    invalidateGenerated();
  }, [sessionId, ruleSelection, invalidateGenerated]);

  const toggleRuleSelected = useCallback((ruleId: number, selected: boolean) => {
    setRuleSelection((prev) => {
      if (!prev) return prev;
      const rules = prev.rules.map((r) => (r.id === ruleId ? { ...r, selected } : r));
      const selectedRuleIds = rules.filter((r) => r.selected).map((r) => r.id ?? 0);
      return { rules, selectedRuleIds };
    });
  }, []);

  const setAllRulesSelected = useCallback((ruleIds: number[], selected: boolean) => {
    setRuleSelection((prev) => {
      if (!prev) return prev;
      const idSet = new Set(ruleIds);
      const rules = prev.rules.map((r) =>
        idSet.has(r.id ?? 0) ? { ...r, selected } : r,
      );
      const selectedRuleIds = rules.filter((r) => r.selected).map((r) => r.id ?? 0);
      return { rules, selectedRuleIds };
    });
  }, []);

  const loadMapping = useCallback(async () => {
    if (!sessionId) return;
    // Refresh when unset or when segments were dropped (partial save / stale state).
    if (mapping && mapping.segments?.length) return;
    const m = await api<MappingConfig>('GET', `/sessions/${sessionId}/mapping`);
    setMapping(m);
  }, [sessionId, mapping]);

  const saveMapping = useCallback(async () => {
    if (!sessionId || !mapping) return;
    const saved = await api<MappingConfig>('PUT', `/sessions/${sessionId}/mapping`, mapping);
    setMapping(saved);
  }, [sessionId, mapping]);

  const runGenerateAndValidate = useCallback(async () => {
    if (!sessionId) return;
    setError(null);
    invalidateGenerated();
    updateJob(emptyJob());

    const cfg: GenerationConfig = {
      ...generation,
      segmentsMapping: deriveSegmentsMapping(mapping?.segments || []),
      segmentMappings: mapping?.segments || [],
      labelMappings: mapping?.labelMappings || [],
    };

    try {
      const genJob = await runJob(
        sessionId,
        `/sessions/${sessionId}/generate`,
        cfg,
        'Policy generation',
        updateJob,
      );
      if (genJob.state === 'failed') {
        setError(genJob.error || 'Generation failed');
        return;
      }
      const p = await api<PoliciesResult>('GET', `/sessions/${sessionId}/policies`);
      setPolicies(p);

      const valJob = await runJob(
        sessionId,
        `/sessions/${sessionId}/validate`,
        {},
        'Policy validation',
        updateJob,
      );
      if (valJob.state === 'failed') {
        setError(valJob.error || 'Validation failed');
        return;
      }
      const v = await api<ValidationResult>('GET', `/sessions/${sessionId}/validation`);
      setValidation(v);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [sessionId, generation, mapping, invalidateGenerated, updateJob]);

  const loadPolicyFile = useCallback(
    async (filename: string) => {
      if (!sessionId) return;
      const preview = await api<PolicyPreview>(
        'GET',
        `/sessions/${sessionId}/policies?file=${encodeURIComponent(filename)}`,
      );
      setPolicyPreview(preview);
    },
    [sessionId],
  );

  const value = useMemo(
    () => ({
      sessionId,
      about,
      error,
      setError,
      sourceType,
      setSourceType,
      connection,
      setConnection,
      testResult,
      summary,
      analysis,
      analysisStarted,
      ruleSelection,
      mapping,
      setMapping,
      generation,
      setGeneration,
      policies,
      policyPreview,
      validation,
      pendingUploadFile,
      setPendingUploadFile,
      uploadFileName,
      job,
      initSession,
      testConnection,
      submitSource,
      ensureAnalysis,
      loadRuleSelection,
      saveRuleSelection,
      toggleRuleSelected,
      setAllRulesSelected,
      loadMapping,
      saveMapping,
      runGenerateAndValidate,
      loadPolicyFile,
      invalidateGenerated,
      connectionPayload,
    }),
    [
      sessionId,
      about,
      error,
      sourceType,
      connection,
      testResult,
      summary,
      analysis,
      analysisStarted,
      ruleSelection,
      mapping,
      generation,
      policies,
      policyPreview,
      validation,
      pendingUploadFile,
      uploadFileName,
      job,
      initSession,
      testConnection,
      submitSource,
      ensureAnalysis,
      loadRuleSelection,
      saveRuleSelection,
      toggleRuleSelected,
      setAllRulesSelected,
      loadMapping,
      saveMapping,
      runGenerateAndValidate,
      loadPolicyFile,
      invalidateGenerated,
      connectionPayload,
      setConnection,
      setGeneration,
    ],
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionContextValue {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error('useSession must be used within SessionProvider');
  return ctx;
}

export type { LabelMapping, SegmentMapping };
