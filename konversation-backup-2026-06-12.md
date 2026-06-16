# Konversations-Backup & Kontext-Handoff

> Zweck: Vollständiger Gesprächsstand zum Wiederaufnehmen in einem neuen
> Kontextfenster. Fasst zusammen, was besprochen, entschieden und erstellt
> wurde. Stand: 12. Juni 2026.

---

## Projekt-Überblick

**Bachelorarbeit:** *Sicherheit von LLMs mit Datenbankzugriff — Red-Teaming und
Defense-in-Depth im Unternehmenskontext.*

LLM-Chatbots erhalten per Natural-Language-to-SQL direkten DB-Zugriff. Das
erzeugt eine Angriffsfläche (Prompt Injection → Datenabfluss / SQL-Manipulation
/ unautorisierte Writes). Die Arbeit misst **wie wirksam** gestaffelte
Abwehrschichten sind und **was sie kosten** (Latenz/Energie).

### Dateien im Workspace (`c:\Users\T15341A\dev\bachelorarbeit\`)
- `brainstorm.md` — erste Brainstorm-Fassung (enthält veraltetes OWASP-Mapping 2023/24).
- `brainstorm2.md` — **konsolidierte Hauptfassung**: Forschungsfragen, Hypothesen, korrektes OWASP-2025-Mapping, Defense-Pipeline, Hybrid-Architektur, Oracle, Metriken, Reproduzierbarkeit.
- `literaturrecherche.md` — 11 aufbereitete wissenschaftliche Quellen.
- `themenvorstellung-folien.md` — 10-Folien-Gerüst für die Themenvorstellung.
- `bedrohungsmodell.md` — **neu erstellt in dieser Session** (siehe unten).
- `konversation-backup-2026-06-12.md` — dieses Dokument.

---

## Forschungsfragen (aus brainstorm2.md)

- **FF1 — Wirksamkeit:** Wie stark senkt jeder Defense-Layer (System-Prompt,
  Input-Guardrail, DB-Least-Privilege) + Kombination die Attack Success Rate
  (ASR) ggü. Baseline, über LLM01/02/05/06?
- **FF2 — Kosten-Trade-off:** Welcher inkrementelle Preis (Latenz TTFT/E2E,
  Energie Wh/Anfrage) pro Layer, im Verhältnis zur ASR-Reduktion?
- **FF3 — Architektur vs. Modell-Guardrails:** Bietet infrastrukturseitige
  Härtung (RLS, Views) mehr marginale Sicherheit als LLM-seitige Maßnahmen bei
  geringeren Latenzkosten?

**Kernhypothese H3c:** Deterministische DB-Härtung schlägt probabilistische
LLM-Guardrails beim Sicherheits-/Kosten-Verhältnis — für Ausführungs-/Schreib-
Angriffe (LLM05/06). Für reine Leseexfiltration (LLM02) aus legitim lesbaren
Tabellen bleiben A/B nötig.

---

## OWASP LLM Top 10 (2025) — korrigiertes Mapping
- **LLM01** Prompt Injection (direkt + indirekt/stored)
- **LLM02** Sensitive Information Disclosure (Datenabfluss)
- **LLM05** Improper Output Handling (ungefilterte SQL-Ausführung)
- **LLM06** Excessive Agency (unautorisierte Writes)

---

## Infrastruktur & Tooling

**Hardware:** NVIDIA H200 (141 GB VRAM), paralleles Hosting via vLLM.
- Target LLM (klein, schnell, z. B. Qwen3-14B) ~15–28 GB — Port 8000.
- Attacker LLM (groß, quantisiert, 70B-Klasse) ~45–80 GB — Port 8001.
- Energie-Runs: Attacker pausieren (Verbrauch nicht vermischen).

**VM-Status (vom Nutzer bestätigt):** Ubuntu 24.04, root, GPU per Passthrough
durchgereicht und sichtbar, NVIDIA-Treiber bereits installiert. Setup-Stil:
Schritt-für-Schritt-Anleitung.

**Red-Teaming-Tools:** Promptfoo (Haupt-Framework: Crescendo, Hydra, GOAT),
garak (Baseline-Nullmessung). PyRIT ausgeschlossen.

**Oracle (deterministisch, statt instabilem LLM-Judge):** DB-Statement-Log
(`log_statement=all`), State-Diff, Canary-Token, korreliert über Trace-ID.
Hybrid-Provider: reales FastAPI-Gateway als System-under-Test (Latenz/Kosten),
entkoppeltes Oracle für Sicherheitsmetriken.

---

## Installations-Liste (in dieser Session erarbeitet)

Reihenfolge für die Ubuntu-24.04-VM:
1. **System-Pakete:** `build-essential git curl wget tmux htop python3.12 python3.12-venv python3-pip`.
2. **`uv`** als schneller Paketmanager; **3 getrennte venvs** (vLLM / Gateway / garak — Dependency-Konflikte vermeiden).
3. **vLLM:** `uv pip install vllm`; HF-Login (`hf auth login`), Llama ist gated → Zugriff vorher beantragen. Beide Modelle parallel via `vllm serve ... --gpu-memory-utilization`.
4. **PostgreSQL 16:** `apt install postgresql postgresql-contrib`; `log_statement = 'all'` für Oracle.
5. **Gateway-venv:** `fastapi uvicorn[standard] httpx psycopg[binary] pydantic pynvml`.
6. **Promptfoo:** Node 20 LTS via NodeSource, `npm install -g promptfoo`; vLLM als OpenAI-kompatibler Provider (`http://localhost:8000/v1`).
7. **garak:** eigenes venv, `uv pip install garak`.
8. **Energie:** NVIDIA DCGM (höhere Sampling-Rate) oder `pynvml`.

> Offen: Setup als ausführbares `setup.sh` ins Repo legen (noch nicht gemacht).

---

## Betreuer-Feedback (Themenvorstellung) & Klärung

Betreuer forderte Konkretisierung von: Angriffsmodell, Gefahren, wer/wie/welche
Daten; UseCase-Begründung (z. B. DATEV); ob KI Zugriff auf alle oder gekapselte
Daten hat; User-/Angreifer-Setting; Frage „warum nicht jeder ein eigenes LLM?";
neue eigene Sicherheitsschicht-Ideen; und die **zentrale Assurance-Frage**:
„Woher weiß ein skeptischer Endnutzer, dass die Defense funktioniert?"

### Wichtigste Klärung — Datenmodell
Es gibt zwei Welten; nur eine ist forschungswürdig:
- **DB pro User einschränken** → trivial, nichts zu schützen → verworfen.
- **Geteiltes Multi-Tenant-System** mit Zugriff auf *alle* Daten, Zugriffs-
  kontrolle **pro Anfrage im System** → **das ist der gewählte Gegenstand.**

### Nutzer-Entscheidungen in dieser Session
1. **Abstraktion statt Steuer-Domäne:** Generisches **Multi-Tenant-SaaS-
   Marktplatz-Szenario** (Plattform / Händler-„Middleman" / Kunde), übertragbar
   auf Plattform→DATEV, Händler→Kanzlei, Kunde→Mandant. Verschiedene Rollen mit
   klaren Datengrenzen.
2. **Primärer Angreifer = authentifizierter Insider** (Cross-Tenant-Eskalation),
   indirekte Stored Injection als Nebenschiene.
3. **Zentraler Beitrag = Wirksamkeitsmessung der Schichten** (einzeln +
   kombiniert), NICHT die LDAP-Idee. Nutzer betont: er macht „nichts völlig
   Neues", das ist für eine BA okay — Beitrag = rigorose, reproduzierbare,
   deterministisch-gemessene vergleichende Evaluation inkl. Kostenseite.
4. **Defense C aufgewertet:** von „statischer Read-Only-Rolle" zu
   **identitätsgebundener RLS** (LDAP/AD-Rolle wird bis in die DB-Session
   propagiert, RLS filtert pro Anfrage). LDAP war eigene Idee des Nutzers.
5. **Zwei zusätzliche Defense-Ideen gebrainstormt** (als optionale Kandidaten):
   - **DE:** Eingeschränkte Tool-Schnittstelle — nur parametrisierte
     Query-Templates statt freiem SQL (Function-Calling).
   - **DF:** Output-/Egress-Filter — Antwort vor Auslieferung auf fremde
     Canary-Token/PII scannen.

### Assurance-Antwort an Betreuer
Vertrauen entsteht nicht durch „die KI ist brav", sondern durch
**deterministische Garantien an der richtigen Architekturebene + Audit/
Provenance-Transparenz**. Probabilistische Layer (DA/DB) liefern nur Statistik;
deterministische Layer (DC/DE/DF) liefern strukturelle Garantien.

---

## Inhalt von `bedrohungsmodell.md` (in dieser Session erstellt)
Abschnitte: (1) Datenmodell-Entscheidung + „warum nicht eigenes LLM pro Tenant",
(2) abstraktes Marktplatz-Szenario + Übertragbarkeit, (3) DB-Schema +
Berechtigungsmatrix, (4) Akteure legitim vs. Angreifer A1–A4, (5) Angriffsklassen
× OWASP × Gefahren, (6) Abwehr-Layer D0/DA/DB/DC/D++ + Kandidaten DE/DF,
(7) Assurance (probabilistisch vs. deterministisch + Audit), (8) Bezug zu FF1–3,
(9) offene Punkte.

---

## Nächste Schritte / offene Punkte
- [ ] Konkretes DB-Schema + RLS-Policies + Canary-Datensätze (pro Sensitivitäts-
      stufe) finalisieren.
- [ ] Identitäts-Propagation spezifizieren: LDAP/AD → Gateway → DB-Session-Var
      (`SET app.current_user / app.tenant`) → RLS.
- [ ] Entscheiden: DE & DF als eigene Messlayer aufnehmen oder nur diskutieren
      (Matrix-Explosion vermeiden)?
- [ ] „Legitime Anfragen"-Set für False-Positive-Rate / Usability definieren.
- [ ] Modellnamen final pinnen (Qwen3-14B als Target; Attacker-Checkpoint
      verifizieren), HF-Revisions/Commit-Hashes + `models.lock`.
- [ ] `setup.sh` für die VM erstellen (optional).
- [ ] Defense-B-Klassifikator wählen (Llama-Guard-Variante + RegEx-Set).
- [ ] Promptfoo-Konfig: Plugins (`owasp:llm:*`), Strategien, Attacker-Provider
      (lokaler vLLM-Endpoint vs. Remote-Generation).
- [ ] Statistik festlegen: n Wiederholungen, Signifikanztests für H1a/H3a.

---

## Empfohlener Einstieg im neuen Kontextfenster
> „Lies `brainstorm2.md` und `bedrohungsmodell.md`. Wir machen mit dem
> konkreten DB-Schema + RLS-Policies + Canary-Setup weiter (bzw. mit den
> Defense-Ideen DE/DF)." — danach das jeweils Gewünschte ansteuern.
