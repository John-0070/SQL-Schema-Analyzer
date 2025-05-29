# SQL-Schema-Analyzer
An AI-driven tool for advanced SQL schema analysis, anomaly detection, and interactive reporting.

This project provides a comprehensive analysis pipeline for large SQL schema files. It parses CREATE TABLE statements, performs structural and relational analysis, applies machine learning models for anomaly detection, and generates an interactive HTML report for schema audit and optimization.

Features
Structural evaluation of tables, columns, indexes, and constraints

Detection of schema design anomalies using statistical models

Relational integrity checks with cycle detection and graph centrality

Identification of sensitive data fields based on semantic heuristics

Clustering of similar tables using unsupervised learning

Fully rendered HTML report with embedded visualizations and findings

Technologies
Python 3

SQLParse

NetworkX

Scikit-learn

Plotly

PyVis

Jinja2

Multiprocessing

Use Case
Ideal for teams working with large or complex database schemas who need to:

Identify design flaws, bottlenecks, or non-normalized structures

Audit schema for security and compliance risks

Generate actionable insights for database optimization

Create shareable, visual reports for internal reviews or documentation

Output
schema_analysis_report.html: Full dashboard with metrics, issue breakdown, and visualizations

relationships.html: Interactive network graph of table relationships

Getting Started
bash
Copy
Edit
git clone https://github.com/yourname/AdvancedSchemaAnalyzer.git
cd AdvancedSchemaAnalyzer
python3 main.py large_schema.sql
Project Structure and Design Strengths
What’s Solid
Modular class-based design with clear method separation

Parallel processing for efficient handling of large files

Context-aware SQL parsing logic using nested-state tracking

Accurate column-type tagging using semantic heuristics

Effective use of graph theory for dependency and integrity checks

Unsupervised ML models for clustering and anomaly detection

Interactive report generation with modern visual libraries

What Can Be Improved or Added
Constraint Parsing Expansion: Currently minimal; should handle PRIMARY KEY, UNIQUE, CHECK, DEFAULT, and complex FOREIGN KEY clauses more explicitly

More SQL Statement Support: ALTER TABLE, INDEX, VIEW, TRIGGER, and PROCEDURE parsing

ORM Integration: Optional support to connect to a live DB and analyze the introspected schema (SQLAlchemy or direct INFORMATION_SCHEMA)

Unit Tests: Add unit and integration tests for parsers, analyzers, and metrics

CLI Interface: Argparse-based CLI for file input, config toggles, and custom output paths

Configurable Rules Engine: Move rule toggles into a config file or CLI flags

Data Sample Input: Optional CSV or DB sample analysis to infer actual usage stats

CI/CD Integration: Include GitHub Actions or similar for auto-lint, test, and deploy

Plugin Hooks: Framework for custom checks via plugins (security, compliance, naming)

Export Options: Add JSON or CSV exports for CI integration and audits
