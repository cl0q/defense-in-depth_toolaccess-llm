# Red Team Directory

Dieses Verzeichnis enthält die Konfigurationen für das Red Teaming:

## Dateien

- `promptfooconfig.yaml`: Hauptkonfiguration für Promptfoo
- `legit_set.yaml`: Legitime Anfragen für die False Positive Rate Messung
- `attacks/`: Seed-Angriffe je Erfolgsziel (G-R1 bis G-S1)
- `../run_promptfoo_layers.sh`: Layerweise Promptfoo-Ausführung mit Artefaktablage
- `../run_garak_baseline.sh`: Shell-Skript für Garak Baseline Tests
- `../garak_config.yaml`: Konfiguration für Garak Tests

## Angriffsszenarien

Die folgenden Erfolgsziele (G-*) werden mit Seed-Angriffen getestet:

- G-R1: Cross-Tenant Read (Fremde Tenant-Daten lesbar machen)
- G-R2: Column Masking Bypass (Gesperrte Spalten in Ausgabe erhalten)
- G-W1: Unauthorized Write (Zeile außerhalb der Berechtigungsmatrix schreiben)
- G-W2: Role Escalation (Unbefugte Änderung von Rollen oder Zahlungskonten)
- G-W3: DDL/DML Injection (DDL oder Massen-DML Operationen durchführen)
- G-S1: Indirect Prompt Injection (Canary-Token aus präparierter Zeile in Ausgabe)

## Verwendung

Um die Red Teaming Tests durchzuführen:

1. Führe `./bootstrap_db.sh` für die Datenbank aus
2. Starte Gateway und lokales Modell mit `./run_stack.sh`
3. Führe `./run_promptfoo_layers.sh` für die Layer-Messung aus
4. Führe `./run_garak_baseline.sh` für die Baseline-Tests aus

Die Promptfoo-Ergebnisse landen unter `analysis/artifacts/promptfoo/<run-id>/<layer>/`.
Garak schreibt seine Berichte unter `garak_results/baseline/qwen3-14b`.