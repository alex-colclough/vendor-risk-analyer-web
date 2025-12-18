'use client';

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import {
  Download,
  FileJson,
  FileText,
  AlertTriangle,
  CheckCircle,
  XCircle,
  AlertCircle,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useStore } from '@/store';
import { api } from '@/lib/api';
import type { Finding } from '@/types';

const SEVERITY_COLORS = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#16a34a',
};

const SEVERITY_ICONS = {
  critical: XCircle,
  high: AlertTriangle,
  medium: AlertCircle,
  low: CheckCircle,
};

export function ResultsDashboard() {
  const { results, analysisId, analysisStatus } = useStore();

  if (analysisStatus !== 'completed' || !results) {
    return null;
  }

  const frameworkData = results.frameworks.map((fw) => ({
    name: fw.framework,
    coverage: fw.coverage_percentage,
    implemented: fw.implemented_controls,
    partial: fw.partial_controls,
    missing: fw.missing_controls,
  }));

  const severityCounts = results.findings.reduce(
    (acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  const pieData = Object.entries(severityCounts).map(([severity, count]) => ({
    name: severity,
    value: count,
    color: SEVERITY_COLORS[severity as keyof typeof SEVERITY_COLORS],
  }));

  const handleDownloadJson = () => {
    if (analysisId) {
      window.open(api.getExportJsonUrl(analysisId), '_blank');
    }
  };

  const handleDownloadPdf = () => {
    if (analysisId) {
      window.open(api.getExportPdfUrl(analysisId), '_blank');
    }
  };

  return (
    <div className="space-y-6">
      {/* Score and Export */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="md:col-span-2">
          <CardHeader>
            <CardTitle>Overall Compliance Score</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-8">
              <div className="relative w-32 h-32">
                <svg className="w-32 h-32 transform -rotate-90">
                  <circle
                    cx="64"
                    cy="64"
                    r="56"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="12"
                    className="text-muted"
                  />
                  <circle
                    cx="64"
                    cy="64"
                    r="56"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="12"
                    strokeLinecap="round"
                    className={
                      results.overall_compliance_score >= 80
                        ? 'text-green-500'
                        : results.overall_compliance_score >= 60
                        ? 'text-yellow-500'
                        : 'text-red-500'
                    }
                    strokeDasharray={`${
                      (results.overall_compliance_score / 100) * 352
                    } 352`}
                  />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <span className="text-3xl font-bold">
                    {Math.round(results.overall_compliance_score)}%
                  </span>
                </div>
              </div>
              <div className="space-y-2">
                <p className="text-lg font-medium">
                  {results.overall_compliance_score >= 80
                    ? 'Good Compliance'
                    : results.overall_compliance_score >= 60
                    ? 'Moderate Compliance'
                    : 'Needs Improvement'}
                </p>
                <p className="text-sm text-muted-foreground">
                  Based on {results.frameworks.length} framework(s) analyzed
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Export Results</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <Button
              onClick={handleDownloadJson}
              variant="outline"
              className="w-full gap-2"
            >
              <FileJson className="h-4 w-4" />
              Download JSON
            </Button>
            <Button
              onClick={handleDownloadPdf}
              variant="outline"
              className="w-full gap-2"
            >
              <FileText className="h-4 w-4" />
              Download PDF Report
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Framework Coverage */}
      <Card>
        <CardHeader>
          <CardTitle>Framework Coverage</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={frameworkData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis domain={[0, 100]} />
                <Tooltip />
                <Bar dataKey="coverage" fill="hsl(var(--primary))" radius={4} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </CardContent>
      </Card>

      {/* Findings */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="md:col-span-2">
          <CardHeader>
            <CardTitle>Findings ({results.findings.length})</CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-80">
              <div className="space-y-3">
                {results.findings.map((finding, i) => {
                  const Icon =
                    SEVERITY_ICONS[finding.severity as keyof typeof SEVERITY_ICONS];
                  return (
                    <div
                      key={i}
                      className="p-4 border rounded-lg space-y-2"
                    >
                      <div className="flex items-center gap-2">
                        <Icon
                          className="h-5 w-5"
                          style={{
                            color:
                              SEVERITY_COLORS[
                                finding.severity as keyof typeof SEVERITY_COLORS
                              ],
                          }}
                        />
                        <span
                          className="text-xs font-medium uppercase px-2 py-0.5 rounded"
                          style={{
                            backgroundColor:
                              SEVERITY_COLORS[
                                finding.severity as keyof typeof SEVERITY_COLORS
                              ] + '20',
                            color:
                              SEVERITY_COLORS[
                                finding.severity as keyof typeof SEVERITY_COLORS
                              ],
                          }}
                        >
                          {finding.severity}
                        </span>
                        <span className="text-xs text-muted-foreground">
                          {finding.category}
                        </span>
                      </div>
                      <h4 className="font-medium">{finding.title}</h4>
                      <p className="text-sm text-muted-foreground">
                        {finding.description}
                      </p>
                      <p className="text-sm">
                        <span className="font-medium">Recommendation:</span>{' '}
                        {finding.recommendation}
                      </p>
                    </div>
                  );
                })}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Findings by Severity</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-48">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={40}
                    outerRadius={70}
                    paddingAngle={2}
                    dataKey="value"
                    label={({ name, value }) => `${name}: ${value}`}
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Risk Assessment */}
      {results.risk_assessment && (
        <Card>
          <CardHeader>
            <CardTitle>Risk Assessment</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4">
              <div className="text-center p-4 bg-muted rounded-lg">
                <p className="text-sm text-muted-foreground">Security Posture</p>
                <p className={`text-2xl font-bold ${
                  results.risk_assessment.security_posture_score >= 80
                    ? 'text-green-500'
                    : results.risk_assessment.security_posture_score >= 60
                    ? 'text-yellow-500'
                    : 'text-red-500'
                }`}>
                  {results.risk_assessment.security_posture_level}
                </p>
                <p className="text-sm">
                  Score: {results.risk_assessment.security_posture_score}/100
                </p>
              </div>
              <div className="text-center p-4 bg-muted rounded-lg">
                <p className="text-sm text-muted-foreground">Overall Risk</p>
                <p className={`text-2xl font-bold ${
                  results.risk_assessment.overall_risk_score < 25
                    ? 'text-green-500'
                    : results.risk_assessment.overall_risk_score < 50
                    ? 'text-yellow-500'
                    : 'text-red-500'
                }`}>
                  {results.risk_assessment.overall_risk_level}
                </p>
                <p className="text-sm">
                  Score: {results.risk_assessment.overall_risk_score}/100
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Executive Summary */}
      {results.executive_summary && (
        <Card>
          <CardHeader>
            <CardTitle>Executive Summary</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-muted-foreground whitespace-pre-wrap">
              {results.executive_summary}
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
