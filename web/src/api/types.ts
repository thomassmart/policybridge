export interface Summary {
  sourceType?: string;
  nsxVersion?: string;
  vmCount?: number;
  groupCount?: number;
  segmentCount?: number;
  dfwPolicyCount?: number;
  dfwRuleCount?: number;
  serviceCount?: number;
  warnings?: string[];
}

export interface ConnectionView {
  host?: string;
  username?: string;
  insecureSkipVerify?: boolean;
  configured?: boolean;
  hasPassword?: boolean;
}

export interface ConnectPayload {
  host: string;
  username: string;
  password?: string;
  insecureSkipVerify?: boolean;
}

export interface Job {
  id?: string;
  type?: string;
  state: 'idle' | 'running' | 'completed' | 'failed' | 'cancelled';
  progress?: number;
  message?: string;
  error?: string;
  logs?: string[];
}

export interface ServicePort {
  name: string;
  protocol?: string;
  ports?: string;
}

export interface DFWRuleRow {
  id?: number;
  name?: string;
  policy?: string;
  category?: string;
  sources?: string[];
  destinations?: string[];
  services?: string[];
  servicePorts?: ServicePort[];
  action?: string;
  selected?: boolean;
}

export interface RuleSelectionView {
  rules: DFWRuleRow[];
  selectedRuleIds: number[];
}

export interface LintFinding {
  ruleId?: string;
  category?: string;
  direction?: string;
  shadowingRuleIds?: string;
  description?: string;
}

export interface AnalysisResult {
  connectivityJson?: unknown;
  connectivity?: unknown;
  dfwRules?: DFWRuleRow[];
  lint?: {
    shadowedRules?: LintFinding[];
    ineffectiveRules?: LintFinding[];
  };
  insights?: {
    warnings?: string[];
    emptyGroups?: string[];
  };
}

export interface SegmentMapping {
  segmentId: string;
  segmentName: string;
  targetKind: 'udn' | 'nad' | 'pod-network';
  targetName: string;
}

export interface LabelMapping {
  nsxIdentity: string;
  kind: 'vm' | 'group';
  labelKey: string;
  labelValue: string;
}

export interface MappingConfig {
  segments: SegmentMapping[];
  labelMappings?: LabelMapping[];
}

export interface GenerationConfig {
  endpointsMapping: 'vms' | 'pods' | 'both';
  segmentsMapping: 'pod-network' | 'udns';
  policyOptimizationLevel: 'none' | 'moderate' | 'max';
  synthesizeAdminPolicies?: boolean;
  createDNSPolicy?: boolean;
  hintsInference?: boolean;
  outputFilter?: string[];
  defaultRule?: string;
  segmentMappings?: SegmentMapping[];
  labelMappings?: LabelMapping[];
}

export interface PoliciesResult {
  resourceCounts?: Record<string, number>;
  files?: string[];
}

export interface PolicyPreview {
  filename: string;
  content: string;
}

export interface ComparisonFinding {
  category: string;
  sourceIdentity?: string;
  destinationIdentity?: string;
  protocol?: string;
  portRange?: string;
  severity?: string;
}

export interface ValidationResult {
  comparison?: {
    summary?: {
      exact?: number;
      missing?: number;
      additional?: number;
      uncomparable?: number;
    };
    missing?: ComparisonFinding[];
    additional?: ComparisonFinding[];
    uncomparable?: ComparisonFinding[];
  };
}

export interface AboutInfo {
  version?: string;
  vmwareAnalyzer?: string;
  netpolAnalyzer?: string;
  independenceNotice?: string;
}

export type SourceType = 'connect' | 'upload';

export interface JobState {
  label: string;
  running: boolean;
  progress: number;
  message: string;
  logs: string[];
  error?: string;
}
