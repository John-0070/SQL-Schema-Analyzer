# AdvancedSchemaAnalyzer
AI-driven SQL schema analysis and reporting engine.
Performs structural, relational, and statistical audits on large SQL schema files. Generates interactive HTML dashboards with deep insights into schema design, integrity, and security.

# Overview
AdvancedSchemaAnalyzer is designed to help data engineers, architects, and security analysts audit, visualize, and optimize complex database schemas. It supports:

Pattern-aware SQL parsing

Graph-based relationship analysis

Anomaly detection using unsupervised machine learning

Automatic detection of schema flaws and design anti-patterns

HTML report generation with embedded charts and diagrams

# Features
Analysis Capabilities
Structural Analysis

Column count outlier detection

Index coverage evaluation

Relational Analysis

Foreign key graph modeling

Cycle detection and centrality checks

Statistical Modeling

Unsupervised clustering (DBSCAN)

Outlier detection (IsolationForest)

Security Review

Sensitive data field detection

Flagging of potential compliance risks

# Output
schema_analysis_report.html: Full audit report (interactive)

relationships.html: Standalone foreign key graph viewer

# Technologies Used
Purpose	Library
SQL Parsing	sqlparse
Data Modeling	pydantic
Graph Analysis	networkx
Clustering & ML	scikit-learn
Visualization	plotly, pyvis
Report Generation	jinja2
Parallel Parsing	multiprocessing

# Project Design
# What's Working Well
Clean, modular architecture with a class-based pipeline

Efficient SQL parsing using memory mapping and parallelization

Semantic tagging of columns (e.g., sensitive, identifier)

Use of graph theory for schema dependency evaluation

Machine learning-backed structural clustering and anomaly detection

Report templating with embedded charts and UI logic

# Recommended Improvements
# Area	Recommendation
Constraint Handling	Improve parsing for CHECK, UNIQUE, and multi-column constraints

SQL Coverage	Add support for ALTER, VIEW, TRIGGER, and PROCEDURE

Live DB Support	Integrate SQLAlchemy for runtime schema inspection

Configurable Rules	YAML/JSON-based rule customization or CLI flags

Testing	Add unit and integration tests

CLI Enhancements	Use argparse for argument parsing and custom output locations

CI/CD	Add GitHub Actions for linting, testing, and builds

Data Profiling	Optionally accept data samples for further inference

Plugin System	Hookable architecture for custom checks and metrics

Export Options	Add JSON/CSV export for CI pipelines or audit archives

# Use Cases
Internal DB schema review before production rollout

Security and compliance audits for regulated data systems

Optimization review of existing enterprise schemas

Integration into CI pipelines for continuous schema analysis
