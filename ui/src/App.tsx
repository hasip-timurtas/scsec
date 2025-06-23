import React, { useState, useEffect } from "react";
import {
  ShieldCheckIcon,
  ExclamationTriangleIcon,
  DocumentMagnifyingGlassIcon,
} from "@heroicons/react/24/outline";

interface SecurityIssue {
  rule_name: string;
  severity: "critical" | "high" | "medium" | "low";
  message: string;
  file_path: string;
  line_number?: number;
  code_snippet?: string;
  suggestion?: string;
}

interface SecurityReport {
  metadata: {
    generated_at: string;
    solsec_version: string;
    total_files_scanned: number;
  };
  summary: {
    total_issues: number;
    critical_issues: number;
    high_issues: number;
    medium_issues: number;
    low_issues: number;
  };
  analysis_results: SecurityIssue[];
  recommendations: string[];
}

const SeverityBadge: React.FC<{ severity: string }> = ({ severity }) => {
  const colors = {
    critical: "bg-red-100 text-red-800 border-red-200",
    high: "bg-orange-100 text-orange-800 border-orange-200",
    medium: "bg-yellow-100 text-yellow-800 border-yellow-200",
    low: "bg-green-100 text-green-800 border-green-200",
  };

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border ${
        colors[severity as keyof typeof colors] || "bg-gray-100 text-gray-800"
      }`}
    >
      {severity.toUpperCase()}
    </span>
  );
};

const IssueCard: React.FC<{ issue: SecurityIssue }> = ({ issue }) => {
  return (
    <div className="bg-white p-6 rounded-lg shadow-sm border border-gray-200 hover:shadow-md transition-shadow">
      <div className="flex justify-between items-start mb-3">
        <h3 className="text-lg font-semibold text-gray-900">
          {issue.rule_name}
        </h3>
        <SeverityBadge severity={issue.severity} />
      </div>

      <p className="text-gray-600 mb-3">{issue.message}</p>

      <div className="text-sm text-gray-500 mb-3">
        <span className="font-medium">File:</span> {issue.file_path}
        {issue.line_number && (
          <span className="ml-2">Line {issue.line_number}</span>
        )}
      </div>

      {issue.code_snippet && (
        <div className="bg-gray-50 p-3 rounded-md mb-3">
          <pre className="text-sm text-gray-800 font-mono overflow-x-auto">
            {issue.code_snippet}
          </pre>
        </div>
      )}

      {issue.suggestion && (
        <div className="bg-blue-50 p-3 rounded-md">
          <p className="text-sm text-blue-800">
            <strong>💡 Suggestion:</strong> {issue.suggestion}
          </p>
        </div>
      )}
    </div>
  );
};

const Dashboard: React.FC<{ report: SecurityReport }> = ({ report }) => {
  const { summary } = report;

  const stats = [
    {
      name: "Total Issues",
      value: summary.total_issues,
      color: "text-gray-900",
    },
    { name: "Critical", value: summary.critical_issues, color: "text-red-600" },
    { name: "High", value: summary.high_issues, color: "text-orange-600" },
    { name: "Medium", value: summary.medium_issues, color: "text-yellow-600" },
    { name: "Low", value: summary.low_issues, color: "text-green-600" },
  ];

  return (
    <div className="grid grid-cols-1 gap-5 sm:grid-cols-5">
      {stats.map((stat) => (
        <div
          key={stat.name}
          className="bg-white overflow-hidden shadow rounded-lg"
        >
          <div className="p-5">
            <div className="flex items-center">
              <div className="flex-shrink-0">
                {stat.name === "Total Issues" ? (
                  <DocumentMagnifyingGlassIcon className="h-6 w-6 text-gray-400" />
                ) : (
                  <ExclamationTriangleIcon className="h-6 w-6 text-gray-400" />
                )}
              </div>
              <div className="ml-5 w-0 flex-1">
                <dl>
                  <dt className="text-sm font-medium text-gray-500 truncate">
                    {stat.name}
                  </dt>
                  <dd className={`text-lg font-medium ${stat.color}`}>
                    {stat.value}
                  </dd>
                </dl>
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
};

const App: React.FC = () => {
  const [report, setReport] = useState<SecurityReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedSeverity, setSelectedSeverity] = useState<string>("all");

  useEffect(() => {
    // In a real implementation, this would fetch from an API
    // For demo purposes, we'll use mock data
    const mockReport: SecurityReport = {
      metadata: {
        generated_at: new Date().toISOString(),
        solsec_version: "0.1.5",
        total_files_scanned: 12,
      },
      summary: {
        total_issues: 8,
        critical_issues: 1,
        high_issues: 2,
        medium_issues: 3,
        low_issues: 2,
      },
      analysis_results: [
        {
          rule_name: "integer_overflow",
          severity: "medium",
          message: "Potential integer overflow in arithmetic operation",
          file_path: "src/lib.rs",
          line_number: 42,
          code_snippet: "let result = a + b;",
          suggestion: "Use checked_add() for safe arithmetic",
        },
        {
          rule_name: "missing_signer_check",
          severity: "high",
          message: "Instruction handler missing signer validation",
          file_path: "src/instructions/transfer.rs",
          line_number: 15,
          code_snippet:
            "pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {",
          suggestion: "Add signer validation before processing",
        },
        {
          rule_name: "unchecked_account",
          severity: "critical",
          message: "Account used without proper validation",
          file_path: "src/instructions/withdraw.rs",
          line_number: 28,
          code_snippet:
            "let account_data = unsafe { &mut *account.data.as_ptr() };",
          suggestion: "Add account validation checks",
        },
      ],
      recommendations: [
        "Address critical security issues immediately",
        "Review high-severity findings before deployment",
        "Consider using checked arithmetic operations",
        "Implement comprehensive testing",
      ],
    };

    setTimeout(() => {
      setReport(mockReport);
      setLoading(false);
    }, 1000);
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading security report...</p>
        </div>
      </div>
    );
  }

  if (!report) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <ExclamationTriangleIcon className="h-12 w-12 text-gray-400 mx-auto" />
          <p className="mt-4 text-gray-600">Failed to load security report</p>
        </div>
      </div>
    );
  }

  const filteredIssues =
    selectedSeverity === "all"
      ? report.analysis_results
      : report.analysis_results.filter(
          (issue) => issue.severity === selectedSeverity
        );

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white shadow">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center">
              <ShieldCheckIcon className="h-8 w-8 text-indigo-600" />
              <h1 className="ml-3 text-2xl font-bold text-gray-900">
                Solana Security Report
              </h1>
            </div>
            <div className="text-sm text-gray-500">
              Generated:{" "}
              {new Date(report.metadata.generated_at).toLocaleString()}
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Dashboard */}
        <div className="mb-8">
          <h2 className="text-lg font-medium text-gray-900 mb-4">
            Security Overview
          </h2>
          <Dashboard report={report} />
        </div>

        {/* Filters */}
        <div className="mb-6">
          <div className="flex flex-wrap gap-2">
            {["all", "critical", "high", "medium", "low"].map((severity) => (
              <button
                key={severity}
                onClick={() => setSelectedSeverity(severity)}
                className={`px-3 py-1 rounded-full text-sm font-medium ${
                  selectedSeverity === severity
                    ? "bg-indigo-600 text-white"
                    : "bg-white text-gray-700 hover:bg-gray-50 border border-gray-300"
                }`}
              >
                {severity === "all"
                  ? "All Issues"
                  : severity.charAt(0).toUpperCase() + severity.slice(1)}
              </button>
            ))}
          </div>
        </div>

        {/* Issues */}
        <div className="mb-8">
          <h2 className="text-lg font-medium text-gray-900 mb-4">
            Security Issues ({filteredIssues.length})
          </h2>
          <div className="space-y-4">
            {filteredIssues.length > 0 ? (
              filteredIssues.map((issue, index) => (
                <IssueCard key={index} issue={issue} />
              ))
            ) : (
              <div className="text-center py-12">
                <ShieldCheckIcon className="h-12 w-12 text-green-400 mx-auto" />
                <p className="mt-4 text-gray-600">
                  No issues found for selected severity level
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Recommendations */}
        <div className="bg-blue-50 rounded-lg p-6">
          <h2 className="text-lg font-medium text-blue-900 mb-4">
            📋 Recommendations
          </h2>
          <ul className="space-y-2">
            {report.recommendations.map((rec, index) => (
              <li key={index} className="text-blue-800">
                • {rec}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
};

export default App;
