# Welcome to the APT Detection Project

This project provides a comprehensive and validated set of threat detection rules for the **ELK Stack (Elasticsearch, Logstash, & Kibana)**, designed to identify adversary behaviors across the entire Advanced Persistent Threat (APT) lifecycle.



The primary goal is to equip security analysts and threat hunters with practical, high-fidelity detection logic mapped directly to the **MITRE ATT&CK® framework**. Each rule is built from a structured workflow of threat simulation, log analysis, and rigorous validation to ensure accuracy and minimize false positives.

---

## Getting Started

If you're new to the project, here's the recommended path:


1.  **Understand the Methodology**: Read the **[Project Workflow](overall_workflow.md)** page to learn about the structured process used to create and validate each detection rule.
2.  **Explore the Lifecycle**: Browse the **[APT Threat Lifecycle](apt_lifecycle.md)** to see how detections are mapped to specific adversary tactics.
3.  **Find a Rule**: Go to the **[Rules Created](rules.md)** section for a complete list of all detection rules with their KQL queries.

---

## 📖 Documentation Structure

This documentation is organized into four main sections to help you find what you need quickly.

### Environment Setup
This section provides detailed instructions and configurations for setting up the entire lab environment.

* **[Virtual Machine Setup](setup/vm_setup.md)**

* **[ELK Setup](setup/elk_setup.md)**

* **[Atomic Red Team Setup](setup/art_setup.md)**

### Project Workflow
This section details the **end-to-end methodology** for rule development. It covers the complete cycle from threat simulation with **Atomic Red Team (Windows)** to log analysis, KQL rule creation, and final validation.

* **[View the Full Workflow](overall_workflow.md)**

### APT Threat Lifecycle
This is the strategic overview of the project. It breaks down a sophisticated cyberattack into **12 distinct stages** based on the MITRE ATT&CK framework and links to the relevant detections for each stage.

* **[Explore the Lifecycle](apt_lifecycle.md)**

### Rules Created
This is the central repository for all detection logic. It contains a list of every finalized rule, its purpose, and the KQL query ready for deployment in Kibana.

* **[Browse All Rules](rules.md)**

