# Judging Pitch

## Problem
Ransomware often reveals itself through a sudden filesystem behavior spike: many files are modified, renamed, or deleted in a short period.

## Solution
A lightweight endpoint sensor combines real-time filesystem telemetry, SHA-256 FIM, behavioral scoring, process context, persistent evidence, and a SOC-style dashboard.

## Innovation
The detector uses multiple correlated signals:
- burst volume
- unique files touched
- destructive activity ratio
- extension-changing renames
- integrity mismatches

This is more robust than a single filename/extension rule.

## Demo
Baseline → monitor → safe simulation → alert spike → timeline → integrity verification → response recommendation.

## Judging alignment
**Innovation:** behavioral correlation + evidence-first FIM.  
**Technical:** watchdog, SHA-256, SQLite, anomaly scoring, dashboard.  
**Feasibility:** modular architecture with a clear production telemetry upgrade path.  
**Presentation:** one repeatable, visual, safe demo.
