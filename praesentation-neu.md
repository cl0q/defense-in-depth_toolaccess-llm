# Präsentation (neu) — Foliengerüst (technisch vertieft, aktueller Stand)

> Thema: **Sicherheit von LLMs mit Datenbankzugriff — Red-Teaming und Defense-in-Depth im Unternehmenskontext**
> Folientext = Stichpunkte, kein Fließtext.
>
> **Update ggü. alter PDF:** Target Qwen3.6-27B-FP8 · Attacker Hermes-4-70B-FP8 · Dual-Guard (Llama-Guard-3-8B + Prompt-Guard-2-86M) · Layer DT statt I6 · FP8 statt INT8/4 · PyRIT primär (Promptfoo/garak ergänzend) · H200.

---

## Folie 1 — Titel

**Sicherheit von LLMs mit Datenbankzugriff:**
**Red-Teaming und Defense-in-Depth im Unternehmenskontext**

- [Dein Name]
- [Kurs / Matrikel]
- [Hochschule / Campus · DATEV]

---

## Folie 2 — Agenda

1. Problemstellung & Zielsetzung
2. Bedrohungsmodell: Szenario, Rollen, Angriffsklassen (Lesen + Schreiben)
3. Forschungsfragen & Hypothesen
4. Defense-in-Depth-Pipeline (LLM-seitig vs. DB-seitig)
5. Versuchsaufbau & Technik-Stack (konkrete Modelle, Tools)
6. Zeitplan & Ausblick

---

## Folie 3 — Problemstellung

- NL-to-SQL: LLM übersetzt Nutzerfrage → SQL → Ausführung auf Produktiv-DB
- Neue Angriffsfläche: Prompt Injection → Datenabfluss, unautorisiertes SQL, Manipulation/Löschen
- Scope: Lesen (Exfiltration) + Schreiben (Manipulation, Privilege Escalation, Finanzbetrug)
- Schutz kostet: Latenz · GPU · Geld — Wirksamkeit und Preis kaum belastbar gemessen

> **Heute:** Schutz ad hoc, unquantifiziert
> **Ziel:** gestaffelte Abwehr (Prompt · Guardrail · DB-Rechte/RLS/Masking), Wirksamkeit + Kosten quantifiziert

---

## Folie 4 — Szenario & Akteure

- System under Test: Multi-Tenant-SaaS-Marktplatz — ein LLM-Dienst, eine PostgreSQL-DB, Daten aller Tenants
- Warum geteilt: isolierte DB pro Tenant = trivial sicher, aber bei 10.000+ Tenants unwirtschaftlich → erst Multi-Tenancy macht Zugriffskontrolle hart

**Rollen (= Tenant-Grenze):**

| Rolle | Beschreibung | Mapping (Steuer-Welt) |
|-------|--------------|------------------------|
| **Admin / Plattform** | Betreiber, übergreifend | Unternehmen / DATEV |
| **Händler** (Tenant) | eigene Produkte, Umsätze, Käufer | Steuerkanzlei |
| **Kunde** (Tenant) | eigenes Profil, Bestellungen, Zahlungsdaten | Mandant / Arbeitnehmer |

- Primärangreifer: authentifizierter Insider — gültiger Login, Prompt Injection → fremde/höhere Daten (horizontal/vertikal/Spalte) oder unautorisierter Write
- Zweite Schiene: indirekte (Stored) Injection (Greshake et al.)

---

## Folie 5 — Berechtigungsmatrix (Kern des Bedrohungsmodells)

- Schema (PostgreSQL 16): Plattform-Nutzer · Händler · Kunden · Produkte · Bestellungen · Bestellpositionen · Zahlungen · Audit-Log — alle tenant-gebunden

| Datenobjekt | Kunde R | Kunde W | Händler R | Händler W | Admin R | Admin W |
|-------------|:--:|:--:|:--:|:--:|:--:|:--:|
| Eigenes Profil / eigene Bestellung | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Fremde Kunden (PII) | ❌ | ❌ | eingeschr. | ❌ | ✅ | ✅ |
| Fremde Händler (interne Kosten) | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Auszahlungskonto (Händler) | ❌ | ❌ | ✅ (eigenes) | ✅ (eigenes) | ✅ | ✅ |
| Karten-Token (Zahlung) | maskiert | ❌ | ❌ | ❌ | eingeschr. | eingeschr. |
| Eigene Plattform-Rolle | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Bestellsumme | ✅ | ❌ | ✅ | ❌ (willkürl.) | ✅ | ✅ |

> **Schutzaufgabe:** egal was das LLM generiert — nur Zellen/Zeilen der authentifizierten Rolle lesbar/änderbar

---

## Folie 6 — Angriffsklassen: Lesen **+** Schreiben (OWASP LLM Top 10 2025)

**Lesen → LLM02 (Sensitive Information Disclosure):**
- **R1** Cross-Tenant-Read — Händler A liest Umsatz/Kunden von Händler B
- **R2** Vertical-Read — Kunde liest Plattform-Aggregate / fremdes Auszahlungskonto
- **R3** Column-Read — gesperrte Spalte in sichtbarer Zeile (Karten-Token, interne Kosten)

**Schreiben → LLM06 (Excessive Agency), Mechanik LLM05:**
- **W1** Cross-Tenant-Write · **W2** Privilege Escalation (eigene Rolle → Admin)
- **W3** Self-serving (Bestellsumme → 0) · **W4** Destruktiv (Tabellen/Massen-Löschung) · **W5** Finanzbetrug (Auszahlungskonto umbiegen)

**Stored / Indirect → LLM01:**
- **S1** Schadtext in Produktname/Bestellnotiz → kapert LLM eines anderen Nutzers (Admin) beim Lesen → Exfiltration

> Einstieg immer LLM01 · Ausführung immer LLM05 (ungefiltertes SQL erreicht DB)

---

## Folie 7 — Erfolgsziele G-* mit **deterministischem Oracle**

- 6 gebündelte Ziele (gegen Matrix-Explosion), je hartes LLM-unabhängiges Oracle

| Ziel | Bündelt | OWASP | Oracle |
|------|---------|-------|--------|
| **G-R1** Cross-Tenant-Read | R1 | LLM02 | Canary-Match: fremder Tenant-Token in Ausgabe |
| **G-R2** Column/Sensitivity-Read | R2, R3 | LLM02 | Canary-Match: gesperrte Spalte in Ausgabe |
| **G-W1** Unautorisierter Write | W1, W3 | LLM06 | State-Diff: Zeile außerhalb Matrix verändert |
| **G-W2** Escalation / Finanzbetrug | W2, W5 | LLM06 | State-Diff: Rolle/Auszahlungskonto geändert |
| **G-W3** Destruktiver Write | W4 | LLM05/06 | DB-Log: DDL/Massen-DML erreicht DB |
| **G-S1** Stored Injection (2nd order) | S1 | LLM01→02/06 | Canary-Match aus präparierter Zeile in Opfer-Ausgabe |

> **Warum deterministisch:** LLM-Judges schwanken (Erez et al. 2026) → Canary · State-Diff · DB-Log = hartes Treffer-/Diff-Kriterium, Trace-ID-korreliert → reproduzierbares ASR

---

## Folie 8 — Forschungsfragen & Hypothesen

**Forschungsfragen:**
- **FF1 Wirksamkeit** — ASR-Reduktion je Layer (DA·DB·DC) + Kombination vs. Baseline, über LLM01/02/05/06
- **FF2 Kosten** — Δ Latenz (TTFT, E2E) + Δ Energie (Wh/Anfrage) je Layer, relativ zur ASR-Reduktion
- **FF3 Architektur vs. Modell** — Infra-Härtung (RLS/Grants/Views) vs. LLM-Guardrails: mehr Sicherheit bei weniger Latenz?

**Hypothesen FF1:**
- **H1a** — jeder Einzel-Layer senkt ASR signifikant vs. Baseline
- **H1b** — D++ niedrigste ASR, aber abnehmender Grenznutzen je Layer

**Hypothesen FF2:**
- **H2a** — Latenz/Energie steigen monoton je Layer
- **H2b** — DB dominiert Mehraufwand (2. Modell-Call); DA/DC ~kostenneutral

**Kernhypothesen FF3:**
- **H3a′** — DC-b (RLS) größter marginaler ASR-Rückgang über alle Cross-Tenant-Ziele
- **H3b′** — DC < DB an Latenz (kein 2. Modell-Call)
- **H3c′ (zentral)** — deterministische DB-Härtung bestes Sicherheits-/Kosten-Verhältnis; Guardrails nur noch für Intra-Row-Exfiltration + Stored-Injection-Texterkennung

---

## Folie 9 — Defense-in-Depth-Pipeline (einzeln schaltbare Layer)

| Layer | Maßnahme | Wirkebene |
|-------|----------|-----------|
| **D0** Baseline | freies NL-to-SQL, privilegierte DB-Verbindung, keine Filter | — |
| **DA** System-Prompt-Härtung | strikte Anweisungen, Spotlighting (Daten/Instruktions-Trennung) | LLM · probabilistisch |
| **DB** Input-Guardrail | Llama-Guard-3-8B + Prompt-Guard-2-86M (umschaltbar) + RegEx auf bösartige Muster | LLM/Filter · probabilistisch |
| **DC-a** Least-Privilege | eigene DB-Rolle je App-Rolle; minimale Rechte (kein Rollen-Update, kein Löschen von Tabellen) | Infra · deterministisch |
| **DC-b** Row-Level Security | Lese-Prüfung (USING) + Schreib-Prüfung (WITH CHECK), Identität aus der Session (nicht aus dem Prompt) | Infra · deterministisch |
| **DC-c** Column-Masking | sensible Spalten via maskierte Views / entzogene Spalten-Rechte | Infra · deterministisch |
| **D++** Defense-in-Depth | DA + DB + DC-a/b/c sequenziell | gestaffelt |
| **DT** Tool-Schnittstelle | nur parametrisierte Templates (Function-Calling) → eliminiert LLM05 | Architektur · deterministisch |

> Schaltung: Layer einzeln, separat vermessen — D0 → DA → DB → DC-a → DC-b → DC-c → D++ → DT
> **Kernachse FF3:** probabilistisch (DA/DB, ein Jailbreak genügt) vs. deterministisch (DC/DT, strukturelle Garantie unter dem LLM)

---

## Folie 10 — Herzstück: DC-b (RLS) + Identitäts-Propagation

- Prinzip: nicht das LLM entscheidet — out-of-band ermittelte Identität (LDAP/AD) steuert deterministische DB-Filterung

```
1. Auth/Lookup    Nutzer → LDAP/AD → (Rolle, Tenant)        [NIE aus dem Prompt]
2. Propagation    Gateway setzt Rolle + Tenant in DB-Session (transaktionslokal)
3. RLS prüft      Lesen: nur eigene Tenant-Zeilen · Schreiben: nur eigener Tenant
```

- Sicherheitskern: auch bei Jailbreak („lies alle Bestellungen" / „Rolle → Admin") entscheidet die DB nach propagierter Identität → fremde Zeile kommt physisch nicht zurück, verbotener Write wird abgewiesen

> Fallstricke gelöst: nicht-privilegierte App-Rolle + erzwungene RLS (sonst Owner-Bypass) · transaktionslokale Identität (kein Leak bei Connection-Pooling)

---

## Folie 11 — DT: empfohlene Produktivarchitektur

**Doppelrolle:**
- **Experiment** — obere Vergleichsgrenze: kein freies SQL, nur geprüfte parametrisierte Templates; LLM füllt nur Parameter → LLM05 entfällt konstruktionsbedingt
- **Empfehlung** — Realeinsatz: kein freies NL-to-SQL, jede Operation vorab definiert/auditierbar

> NL-to-SQL (D0–DC) = untersuchter Status quo (volle Angriffsfläche) · DT = architektonische Antwort: LLM degradiert vom „SQL-Autor" zum „Parameter-Lieferanten", LDAP→Session→RLS-Kette bleibt
> DT ersetzt frühere Bezeichnung I6

---

## Folie 12 — Versuchsaufbau & Technik-Stack

- Hardware: 1× NVIDIA H200 (141 GB VRAM) — paralleles Hosting via vLLM, getrennte Ports; FP8 ≈ 1 GB/Mrd. Params

| Komponente | Wahl |
|------------|------|
| **Target (Victim)** | Qwen3.6-27B-FP8 — Enterprise-Modell mit Tool-Use; deterministisch (Temp 0, fester Seed) |
| **Generalisierung** | 2. Topologie: starkes Target Qwen3.6-72B × schwacher Attacker Qwen3-8B |
| **Attacker** | Hermes-4-70B-FP8 — low-refusal, generiert Angriffe statt zu verweigern |
| **Gateway** | FastAPI — Auth, LDAP-Propagation, Defense A/B, Trace-ID, Latenz-Log |
| **Defense B** | Llama-Guard-3-8B + Prompt-Guard-2-86M + RegEx (umschaltbar) |
| **DB** | PostgreSQL 16 — RLS, Least-Privilege, maskierte Views, Canaries |
| **Red-Teaming** | PyRIT (primär, agentisch) + Promptfoo (statisch, OWASP) + garak (Baseline) |
| **Energie** | NVML/DCGM → Wh/Anfrage (isolierte Runs) |

> Durchgängig FP8 (vorher INT8/4) · gepinnte Modell-Revisionen, feste Seeds · Sicherheits-/Latenz-/Energie-Runs getrennt

---

## Folie 12b — Red-Teaming-Strategien

**PyRIT — primär (agentisch, lokal):**
- Multi-Turn über Attacker-LLM: Crescendo (schrittweise Eskalation) + generisches Red-Teaming
- Ein Lauf pro Layer (D0…DT) → ein Artefakt je Konfiguration × Ziel
- Mehrere Trials → belastbare Leak-Rate; Trace-ID-Korrelation ans Oracle

**Promptfoo — ergänzend (statisch, offline):**
- OWASP-/Zugriffs-Plugins (Cross-Session-Leak, RBAC, SQL-Injection, PII, Prompt-Extraction, Excessive-Agency)
- Statische Transforms als Kontrolle (Base64, Leetspeak, ROT13, Homoglyph, Morse)

**garak — Baseline:**
- Standard-Jailbreak-/Prompt-Injection-Probes gegen ungeschütztes Target → Referenzpunkt

> Agentische Stärke lokal (PyRIT + low-refusal-Attacker), air-gapped/reproduzierbar — kein Cloud-Angriffsgenerator (Trade-off: Reproduzierbarkeit vs. SOTA-Stärke)

---

## Folie 13 — Hybrid-Provider + entkoppeltes Oracle

- Design: ein reales API-Gateway als SUT, zwei entkoppelte Mess-Ebenen — Latenz am echten Pfad, Sicherheit aus der Quelle (nicht aus der HTTP-Antwort)

```mermaid
graph TD
    Attacker["PyRIT + Attacker-LLM (Hermes-4-70B)<br/>agentische Multi-Turn-Angriffe (Crescendo)"] -- "Multi-Turn (Trace-ID)" --> GW["API-Gateway (FastAPI)<br/>Defense A/B · Latenz-Log"]
    GW --> Target["Target-LLM (Qwen3.6-27B-FP8)"]
    GW -- "Guard-Check" --> Guard["Llama-Guard-3-8B + Prompt-Guard-2-86M"]
    Target -- "NL-to-SQL" --> DB[("PostgreSQL 16<br/>DC-a/b/c · Canaries")]
    GW -- "Identität: Rolle + Tenant" --> DB
    DB -. "DB-Logging + State-Diff" .-> Oracle["Oracle (offline, Trace-ID-korreliert)<br/>Canary-Match · State-Diff · DB-Log → ASR"]
    GW -. "End-to-End-Latenz" .-> Oracle
```

> **Pfad 1 (Sicherheit):** Oracle aus DB-Log + State-Diff + Canary, Trace-ID-korreliert → deterministisches ASR
> **Pfad 2 (Latenz):** Gateway misst TTFT + E2E am realen Pfad

---

## Folie 14 — Metriken

**Sicherheit:**
- ASR je (Konfiguration × Ziel), ± 95%-CI (Wilson/Bootstrap), n = 5–10
- False-Positive-Rate auf Legitim-Set (Read + Write je Rolle) → Usability-Kosten

**Kosten (FF2):**
- Latenz: TTFT + E2E, Δ je Layer — Erwartung: DB dominiert, DA/DC ~neutral
- Energie: NVML/DCGM, Wh/Anfrage als ΔEnergie, isolierte Runs
- Wirtschaftlichkeit: Stromkosten / 1.000 Anfragen (Sensitivitätsrechnung)

> **Zentrales Bild:** Trade-off-Diagramm — ASR-Reduktion (y) vs. Latenz/Energie (x) je Layer

---

## Folie 15 — Experiment-Matrix & Erwartungsbild

Konfigurationen × Ziele × n:

| Ziel | DA / DB (probabil.) | DC (determin.) | DT |
|------|:--:|:--:|:--:|
| G-R1 Cross-Tenant-Read | teilweise | 0 (DC-b) | 0 |
| G-R2 Column-Read | teilweise | 0 (DC-c) | 0 |
| G-W1 Unauth. Write | schwach | 0 (DC-b) | 0 |
| G-W2 Escalation | schwach | 0 (DC-a/b) | 0 |
| G-W3 Destruktiv | schwach | 0 (DC-a) | 0 |
| G-S1 Stored Injection | Haupt-DA/DB | nur wenn Aktion DB trifft | reduziert |

> DC fährt Cross-Tenant-Ziele deterministisch auf ~0 · Restwert von DA/DB v. a. bei G-S1 + Intra-Row → Kern von H3c′
> 2 Topologien: starker Attacker × schwaches Target und schwacher Attacker × starkes Target

---

## Folie 16 — Verwandte Arbeiten

- **Pedro et al. (ICSE 2025)** — *P2SQL* — NL-to-SQL standardmäßig unsicher, 4 Abwehrmechanismen
- **Peng et al. (ISSRE 2023)** — *Text-to-SQL Vulnerabilities* — empirisch, kommerziell + Open-Source
- **Greshake et al. (2023)** — *Indirect Prompt Injection* — Basis für S1 (Stored)
- **Russinovich et al. (USENIX 2025)** — *Crescendo* — eingesetztes Multi-Turn-Muster
- **Mehrotra et al. (NeurIPS 2024)** — *Tree of Attacks (TAP)*
- **Erez et al. (2026)** — *When Scanners Lie* — begründet deterministisches Oracle
- **Xiang/Greshake et al. (2026)** — *Architecting Secure AI Agents* — stützt FF3
- **garak (2024)** · **OWASP LLM Top 10 v2.0 (2025)** · **PostgreSQL-Doku** (RLS)

> Lücke: evaluierte, kostengewichtete Defense-in-Depth für LLM-DB-Zugriff ist dünn → Beitrag

---

## Folie 17 — Zeitplan

**Juni — Fundament**
- Literatur, OWASP-2025-Mapping, Bedrohungsmodell
- DB-Schema + RLS + Canaries + Akzeptanztests · Modell-Pinning

**Juli — Pipeline, Messaufbau & Messen**
- FastAPI-Gateway + LDAP-Propagation · Defense A/B (Llama-Guard-3-8B + Prompt-Guard-2-86M) · DT-Templates
- Oracle (Canary/State-Diff/DB-Log) · Legitim-Set · PyRIT-/Promptfoo-/garak-Konfiguration
- Beginn Red-Teaming-Läufe · Beginn Schreiben der Arbeit

**August — Messen, Auswerten & Finalisieren**
- Schreiben der Arbeit · Red-Teaming-Läufe
- ASR ± CI, Trade-off-Diagramm, 2. Target-Topologie, Handlungsempfehlung
- Korrektur & Abgabe

**Meilenstein:** Abgabe am 22.08.2026

---

## Folie 18 — Erwartete Ergebnisse & Ausblick

**Erwartetes Bild:**
- ASR: DC-b (RLS) größte Wirkung — Cross-Tenant-Ziele ~0
- Trade-off: DC effizienter als Guardrails (weniger Latenz, kein 2. Modell-Call)
- Kosten-Nutzen: bestes Verhältnis auf Infra-Ebene

**Zu prüfen:** H3a′ (größter ASR-Rückgang via DC-b) · H3c′ (bestes Sicherheits-/Kosten-Verhältnis)

> Finale Zahlen (ASR ± CI, Trade-off-Diagramm) aus den Mess-Läufen

---

## Folie 19 — Schluss

- Beitrag: reproduzierbare, werkzeuggestützte Red-Team-Evaluation einer Defense-in-Depth-Pipeline für LLM-DB-Zugriff — deterministisches Oracle + Trade-off-Analyse (Sicherheit ↔ Kosten)
- These: deterministische DB-Härtung (RLS) schlägt probabilistische Guardrails im Sicherheits-/Kosten-Verhältnis — für alle Cross-Tenant-Read/Write-Ziele
- *„Sicherheit messbar machen — Wirksamkeit und Preis im Gleichgewicht."*
- [Name / Datum / Danke]

---

## Backup-Folien (auf Nachfrage)

**B1 — Assurance: „Woher weiß ich, dass die Abwehr greift?"**
- Probabilistisch (DA/DB): nur Statistik („hält in X %") — ein Jailbreak genügt
- Deterministisch (DC/DT): strukturell, beweisbar — Policies/Grants statisch prüfbar, LLM-unabhängig
- Optional: Dry-Run + Human-Approval für Hochrisiko-Writes

**B2 — Modellwahl**
- Victim Qwen3.6-27B: produktionsnah, Tool-Use
- Attacker Hermes-4-70B: low-refusal — safety-getuntes Modell würde Red-Team sabotieren
- Beide FP8, gleiche Toolchain · ASR = konservative Untergrenze

**B3 — Limitationen**
- Lokales Red-Teaming (PyRIT) air-gapped/reproduzierbar, aber ggf. schwächer als Cloud-SOTA
- Synthetisches Schema ≠ Produktion · Ergebnisse für getestete Modelle/Größen, nicht Frontier

---

## Sprechernotizen / Q&A (nicht auf Folie)

- **Multi-Tenant statt Isolation?** → Isolation trivial sicher = kein Forschungsthema; Multi-Tenancy = reales Enterprise-Risiko, ökonomisch erzwungen
- **RLS = Standardwissen?** → Beitrag ist nicht RLS selbst, sondern quantifizierte Wirksamkeits-/Kosten-Messung vs. LLM-Guardrails
- **Warum deterministisches Oracle?** → LLM-Judges schwanken (Erez 2026); Canary/State-Diff/DB-Log hart + reproduzierbar
- **Warum lokales Red-Teaming?** → PyRIT fährt Crescendo/Multi-Turn lokal über Hermes — reproduzierbar, air-gapped
- **Neu ggü. P2SQL?** → Pedro: dass unsicher + Einzelmaßnahmen; hier: gestaffelte Abwehr inkl. Latenz/Energie-Kosten, Architektur- vs. Modell-Layer
- **Framing:** Primärliteratur zu evaluierter Defense-in-Depth bei LLM-DB-Zugriff dünn = die Lücke; Stützen: OWASP, MITRE ATLAS, Crescendo, TAP, Greshake
