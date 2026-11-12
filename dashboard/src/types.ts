export interface RuleStats {
  rule_id: string;
  findings: number;
  open: number;
  triaged: number;
  false_positives: number;
  accepted_risk: number;
  fixed: number;
  fp_rate: number | null;
  median_time_to_triage_s: number | null;
}

export interface Totals {
  findings: number;
  triaged: number;
  false_positives: number;
  fp_rate: number | null;
  median_time_to_triage_s: number | null;
}

export interface StatsResponse {
  rules: RuleStats[];
  totals: Totals;
}
