"""Report generation services (M10.B; ADR-034; Tasks 10.2-10.4).

Populated across Stage 3: ``context.py`` (ReportContext assembler; C2),
``json_report.py`` + ``sarif.py`` (C2), ``pdf.py`` (C3). The bundled
``schemas/sarif-2.1.0.json`` is used to validate SARIF output for provable
2.1.0 conformance (G3).
"""
