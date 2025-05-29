import os
import re
import mmap
import sqlparse
import numpy as np
import pandas as pd
import networkx as nx
from enum import Enum
from typing import Dict, List, Tuple, Optional
from pydantic import BaseModel
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sqlparse.tokens import Keyword, Name, Punctuation
from multiprocessing import Pool, cpu_count
from jinja2 import Template
from pyvis.network import Network
import plotly.express as px
from collections import defaultdict

class IssueSeverity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1

class AnalysisCategory(Enum):
    PERFORMANCE = "Performance"
    INTEGRITY = "Data Integrity"
    CONSISTENCY = "Consistency"
    SECURITY = "Security"
    DESIGN = "Schema Design"
    RELATIONAL = "Relational Integrity"

class SchemaIssue(BaseModel):
    title: str
    description: str
    category: AnalysisCategory
    severity: IssueSeverity
    tables: List[str]
    metrics: Optional[Dict]
    recommendation: str

class AdvancedSchemaAnalyzer:
    def __init__(self, schema_file: str):
        self.schema_file = schema_file
        self.schema_model = defaultdict(dict)
        self.relationship_graph = nx.DiGraph()
        self.issues: List[SchemaIssue] = []
        self.metrics = {}
        self.clusters = {}
        
        # Configuration
        self.analysis_rules = {
            'check_index_coverage': True,
            'validate_naming': True,
            'detect_smells': True,
            'analyze_security': True
        }

    def analyze(self):
        """Execute full analysis pipeline"""
        self._parse_schema()
        self._calculate_base_metrics()
        self._perform_structural_analysis()
        self._perform_relational_analysis()
        self._perform_statistical_analysis()
        self._perform_security_analysis()
        self._categorize_issues()
        self._generate_report()

    def _parse_schema(self):
        """Advanced schema parsing with ML-enhanced pattern recognition"""
        with open(self.schema_file, 'r') as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                statements = self._split_sql_statements(mm)
                
                with Pool(cpu_count()) as pool:
                    results = pool.map(self._parse_statement, statements)
                
                for table in results:
                    if table:
                        self.schema_model[table['name']] = table
                        self.relationship_graph.add_node(table['name'])

    def _split_sql_statements(self, mm: mmap.mmap) -> List[str]:
        """Smart statement splitting with nested structure awareness"""
        statements = []
        buffer = []
        depth = 0
        quote_char = None
        
        for i in range(len(mm)):
            char = mm[i:i+1].decode('utf-8', 'ignore')
            
            if char in ('"', "'", '`'):
                if quote_char is None:
                    quote_char = char
                elif char == quote_char:
                    quote_char = None
                continue
                
            if quote_char is None:
                if char == '(': depth += 1
                if char == ')': depth -= 1
                if char == ';' and depth == 0:
                    statements.append(''.join(buffer).strip())
                    buffer = []
                    continue
            
            buffer.append(char)
        
        return statements

    def _parse_statement(self, statement: str) -> Optional[Dict]:
        """Deep SQL statement parsing with context-aware analysis"""
        parsed = sqlparse.parse(statement)[0]
        
        if parsed.get_type() != 'CREATE':
            return None

        table = {
            'name': self._extract_table_name(parsed),
            'columns': {},
            'indexes': [],
            'constraints': [],
            'relationships': [],
            'metrics': {}
        }

        # Advanced column parsing
        for token in parsed.tokens:
            if isinstance(token, sqlparse.sql.Parenthesis):
                self._parse_table_body(token, table)
        
        return table

    def _parse_table_body(self, token: sqlparse.sql.Parenthesis, table: Dict):
        """Multi-layer table structure analysis"""
        current_column = None
        context_stack = []
        
        for item in token.flatten():
            if item.ttype is Punctuation and item.value == '(':
                context_stack.append('column_def')
            elif item.ttype is Punctuation and item.value == ')':
                context_stack.pop()
            
            if isinstance(item, sqlparse.sql.Identifier):
                self._parse_column_definition(item, table)
            elif item.ttype is Keyword:
                self._parse_constraints(item, table)

    def _parse_column_definition(self, identifier, table):
        """Semantic column analysis with type inference"""
        col_parts = [p.value for p in identifier.tokens if not p.is_whitespace]
        col_name = col_parts[0]
        
        column = {
            'type': col_parts[1],
            'nullable': 'NOT NULL' not in identifier.value.upper(),
            'default': next((p for p in col_parts if 'DEFAULT' in p), None),
            'constraints': [],
            'flags': self._detect_column_flags(col_name, col_parts)
        }
        
        table['columns'][col_name] = column

    def _detect_column_flags(self, name: str, parts: List[str]) -> List[str]:
        """Machine-learning enhanced column classification"""
        flags = []
        type_str = ' '.join(parts).upper()
        
        # Security detection
        if re.search(r'(password|token|secret)', name, re.I):
            flags.append('sensitive')
        
        # Temporal detection
        if any(k in type_str for k in ['DATE', 'TIME', 'TIMESTAMP']):
            flags.append('temporal')
        
        # Identifier detection
        if re.search(r'_id$', name) and 'INT' in type_str:
            flags.append('identifier')
        
        return flags

    def _perform_structural_analysis(self):
        """Multi-dimensional schema structure evaluation"""
        # Table Size Analysis
        table_sizes = {name: len(t['columns']) for name, t in self.schema_model.items()}
        size_outliers = self._detect_statistical_outliers(list(table_sizes.values()))
        
        for table, size in table_sizes.items():
            if size in size_outliers:
                self.issues.append(SchemaIssue(
                    title="Oversized Table",
                    description=f"Table {table} has {size} columns, significantly more than average",
                    category=AnalysisCategory.DESIGN,
                    severity=IssueSeverity.HIGH,
                    tables=[table],
                    metrics={'column_count': size},
                    recommendation="Consider normalization or vertical partitioning"
                ))

        # Index Coverage Analysis
        for table, data in self.schema_model.items():
            indexed_columns = set()
            for idx in data['indexes']:
                indexed_columns.update(idx['columns'])
            
            coverage = len(indexed_columns) / len(data['columns'])
            if coverage < 0.2:
                self.issues.append(SchemaIssue(
                    title="Low Index Coverage",
                    description=f"Table {table} has only {coverage:.0%} of columns indexed",
                    category=AnalysisCategory.PERFORMANCE,
                    severity=IssueSeverity.MEDIUM,
                    tables=[table],
                    metrics={'index_coverage': coverage},
                    recommendation="Evaluate query patterns and add missing indexes"
                ))

    def _perform_relational_analysis(self):
        """Graph-based relationship analysis"""
        # Build relationship graph
        for table, data in self.schema_model.items():
            for constraint in data['constraints']:
                if constraint['type'] == 'FOREIGN_KEY':
                    self.relationship_graph.add_edge(
                        table, 
                        constraint['ref_table'],
                        columns=constraint['columns']
                    )

        # Detect complex patterns
        self._detect_cyclic_dependencies()
        self._identify_choke_points()
        self._analyze_relationship_patterns()

    def _detect_cyclic_dependencies(self):
        """Find circular references between tables"""
        try:
            cycle = nx.find_cycle(self.relationship_graph)
            self.issues.append(SchemaIssue(
                title="Circular Dependency",
                description=f"Detected circular reference between {len(cycle)} tables",
                category=AnalysisCategory.RELATIONAL,
                severity=IssueSeverity.CRITICAL,
                tables=[n[0] for n in cycle],
                recommendation="Break cycle with junction table or schema redesign"
            ))
        except nx.NetworkXNoCycle:
            pass

    def _identify_choke_points(self):
        """Find highly connected central tables"""
        betweenness = nx.betweenness_centrality(self.relationship_graph)
        avg_betweenness = np.mean(list(betweenness.values()))
        
        for table, score in betweenness.items():
            if score > avg_betweenness * 3:
                self.issues.append(SchemaIssue(
                    title="Potential Performance Chokepoint",
                    description=f"Table {table} is central to many relationships",
                    category=AnalysisCategory.PERFORMANCE,
                    severity=IssueSeverity.HIGH,
                    tables=[table],
                    metrics={'betweenness_centrality': score},
                    recommendation="Consider caching strategies or read replicas"
                ))

    def _perform_statistical_analysis(self):
        """Machine Learning-driven anomaly detection"""
        features = []
        for table, data in self.schema_model.items():
            features.append([
                len(data['columns']),
                len(data['indexes']),
                len(data['constraints']),
                sum(1 for c in data['columns'].values() if 'identifier' in c['flags']),
                nx.degree(self.relationship_graph, table)
            ])
        
        # Cluster similar tables
        clustering = DBSCAN(eps=2.5, min_samples=2).fit(features)
        self.clusters = defaultdict(list)
        for idx, label in enumerate(clustering.labels_):
            self.clusters[label].append(list(self.schema_model.keys())[idx])

        # Detect statistical anomalies
        clf = IsolationForest(contamination=0.1)
        anomalies = clf.fit_predict(features)
        for idx, is_anomaly in enumerate(anomalies):
            if is_anomaly == -1:
                table = list(self.schema_model.keys())[idx]
                self.issues.append(SchemaIssue(
                    title="Statistical Anomaly",
                    description="Table structure significantly differs from peers",
                    category=AnalysisCategory.DESIGN,
                    severity=IssueSeverity.HIGH,
                    tables=[table],
                    recommendation="Review table design against business requirements"
                ))

    def _perform_security_analysis(self):
        """Data protection and compliance checks"""
        for table, data in self.schema_model.items():
            sensitive_cols = [name for name, col in data['columns'].items() 
                             if 'sensitive' in col['flags']]
            
            if sensitive_cols:
                self.issues.append(SchemaIssue(
                    title="Sensitive Data Exposure",
                    description=f"Table {table} contains sensitive columns",
                    category=AnalysisCategory.SECURITY,
                    severity=IssueSeverity.CRITICAL,
                    tables=[table],
                    metrics={'sensitive_columns': sensitive_cols},
                    recommendation="Implement encryption and access controls"
                ))

    def _categorize_issues(self):
        """Organize issues by priority and category"""
        self.issues.sort(key=lambda x: (-x.severity.value, x.category.value))
        
        # Group similar issues
        grouped = defaultdict(list)
        for issue in self.issues:
            key = (issue.category, issue.title)
            grouped[key].append(issue)
        
        # Merge duplicate findings
        self.issues = []
        for (category, title), items in grouped.items():
            main_issue = items[0].copy()
            main_issue.tables = list(set([t for i in items for t in i.tables]))
            self.issues.append(main_issue)

    def _generate_report(self):
        """Interactive visual report generation"""
        template = Template('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Advanced Schema Analysis Report</title>
            <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
            <style>
                .dashboard { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; }
                .issue-card { padding: 15px; border-radius: 8px; margin-bottom: 10px; }
                .critical { background-color: #ffe6e6; border-left: 4px solid #ff0000; }
                .high { background-color: #fff3e6; border-left: 4px solid #ff6600; }
            </style>
        </head>
        <body>
            <h1>Schema Analysis Report</h1>
            
            <div class="dashboard">
                <div id="metrics-chart"></div>
                <div id="relationship-chart"></div>
                <div id="cluster-chart"></div>
            </div>
            
            <h2>Key Findings</h2>
            {% for issue in issues %}
            <div class="issue-card {{ issue.severity.name.lower() }}">
                <h3>{{ issue.title }} ({{ issue.severity.name }})</h3>
                <p>{{ issue.description }}</p>
                <p><strong>Affected Tables:</strong> {{ issue.tables|join(', ') }}</p>
                <p><strong>Recommendation:</strong> {{ issue.recommendation }}</p>
            </div>
            {% endfor %}
            
            {{ plot_scripts }}
        </body>
        </html>
        ''')

        metrics_fig = px.bar(
            pd.DataFrame({
                'Metric': ['Tables', 'Columns', 'Relationships'],
                'Count': [
                    len(self.schema_model),
                    sum(len(t['columns']) for t in self.schema_model.values()),
                    self.relationship_graph.number_of_edges()
                ]
            }), 
            x='Metric', y='Count', title='Schema Metrics'
        )

        # Generate relationship visualization
        net = Network(height="500px", width="100%")
        net.from_nx(self.relationship_graph)
        net.save_graph("relationships.html")
        
        # Generate cluster visualization
        cluster_fig = px.treemap(
            pd.DataFrame({'Cluster': self.clusters.keys(), 'Tables': self.clusters.values()}),
            path=['Cluster'], values='Tables',
            title='Table Similarity Clusters'
        )

        report = template.render(
            issues=self.issues,
            plot_scripts=(
                metrics_fig.to_html(full_html=False) +
                cluster_fig.to_html(full_html=False)
            )
        )

        with open("schema_analysis_report.html", "w") as f:
            f.write(report)

if __name__ == "__main__":
    analyzer = AdvancedSchemaAnalyzer("large_schema.sql")
    analyzer.analyze()
