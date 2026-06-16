# Brainstorming: Bachelorarbeit -- Sicherheit von LLMs mit Datenbankzugriff

Dieses Dokument dient als zentrale Orientierung für den Aufbau, die Durchführung und die wissenschaftliche Strukturierung der Bachelorarbeit.

---

## 1. Nutzung der Infrastruktur (H200 mit 141 GB VRAM)
Mit einer **NVIDIA H200 (141 GB VRAM)** steht eine extrem leistungsstarke Hardware zur Verfügung. Um die Hardwarebeschränkungen einer einzelnen GPU optimal zu nutzen und ein realistisches Enterprise-Szenario abzubilden, teilen wir den VRAM für zwei zeitgleich laufende Modelle auf:

*   **Paralleles Hosting (vLLM):**
    *   **Ziel-System (Target LLM / Opfer):** Ein kleineres, extrem schnelles Modell wie **Qwen 3.5 / 3.6 (z. B. 7B oder 14B)**.
        *   *Argumentation für die Arbeit:* Repräsentiert ein realistisches, wirtschaftliches Enterprise-Szenario für Kunden-Chatbots (geringe Latenz, niedrige Hosting-Kosten).
    *   **Angreifer-System (Attacker LLM):** Ein großes, mächtiges Modell wie **Llama 3.1/4 (70B/Maverick)** oder **Qwen 3.5/3.6 (72B)**.
        *   *Argumentation für die Arbeit:* Ein realer Angreifer wird stets das stärkste verfügbare Modell nutzen, um Abwehrmechanismen zu überwinden ("Threat Actor Realism").
*   **VRAM-Aufteilung (Beispiel):**
    *   Target: Qwen 3.5 (14B) $\rightarrow$ ca. 15–28 GB VRAM.
    *   Attacker: Llama 3.1 (70B, INT8/INT4 quantisiert) $\rightarrow$ ca. 45–80 GB VRAM.
    *   Beide Modelle laufen parallel via vLLM auf unterschiedlichen Ports (z. B. Port 8000 und 8001) und teilen sich die H200.

---

## 2. Systemarchitektur & Testaufbau (Fokus Promptfoo)

Das System wird als geschlossener Testkreislauf aufgebaut:

```mermaid
graph TD
    Attacker[Angreifer LLM / Promptfoo] -- "1. Multi-Turn Angriffe (Hydra/Crescendo)" --> API_Gate[API-Gateway / Defense Layer]
    API_Gate --> TargetLLM[Target LLM: Qwen 3.5/3.6 (14B)]
    TargetLLM -- "2. Tool-Call (NL-to-SQL)" --> DBTool[Database Tool / SQL Generator]
    DBTool -- "3. Führt Query aus" --> DB[(PostgreSQL)]
    DB -- "4. Ergebnisse" --> DBTool
    DBTool --> TargetLLM
    TargetLLM --> API_Gate
    API_Gate -- "5. Evaluation & Logging" --> Attacker
```

### Red-Teaming-Werkzeuge (Zeitoptimiert & fokussiert):
1.  **Haupt-Framework: Promptfoo** (90% der Arbeit)
    *   *Warum:* Deklarative Konfiguration über YAML, native Unterstützung für Multi-Turn-Algorithmen (**Crescendo** für graduelle Eskalation, **Hydra** für pfadbasierte Angriffe mit Backtracking). Liefert direkt fertige HTML-Berichte mit quantitativen Metriken (ASR, Latenz).
2.  **Hilfs-Scanner: garak (NVIDIA)** (10% der Arbeit)
    *   *Warum:* Wird zu Beginn für eine standardisierte "Nullmessung" (Baseline-Scan auf bekannte Jailbreaks/Injections) über das nackte Modell laufen gelassen.
3.  **Ausschluss von PyRIT:** Aus Zeitgründen wird auf PyRIT verzichtet, um die Lernkurve flach zu halten und den Fokus auf Promptfoo-Auswertungen zu legen.

---

## 3. OWASP LLM Top 10 Angriffs-Szenarien im Fokus

Wir fokussieren uns auf die drei kritischsten Schnittstellen zwischen LLM und Datenbank:
*   **LLM01: Prompt Injection (Direkt & Indirekt):** Direkte Manipulation durch den Nutzer im Chat vs. Auslösen von Schadcode durch präparierte Daten innerhalb der PostgreSQL-Datenbank (Stored/Indirect Injection).
*   **LLM02: Insecure Output Handling:** Ungefilterte Ausführung der vom LLM generierten SQL-Befehle (Prompt-to-SQL Injection).
*   **LLM05: Improper Write-Handling:** Ausnutzung von Schreib- oder Löschfunktionen der DB durch das LLM ohne hinreichende administrative Autorisierung des Nutzers.

---

## 4. Abwehrmethoden: Die "A++ Defense-in-Depth" Pipeline

Wir testen nicht nur Einzelmaßnahmen, sondern vergleichen die Baseline mit einer kombinierten Pipeline (Defense D / A++):

1.  **Defense A: System-Prompt-Härtung** (Few-Shot-Beispiele für sicheres Verhalten, strikte Anweisungen zur Tool-Nutzung).
2.  **Defense B: Eingabe-Filter / Guardrails** (Einsatz eines leichtgewichtigen Klassifizierungsmodells wie *Llama-Guard* oder RegEx-Prüfungen auf bösartige SQL-Muster im Input).
3.  **Defense C: Datenbank-Einschränkungen** (PostgreSQL Least-Privilege-Prinzip: Read-Only-Rollen für den Chatbot, Nutzung von Views statt direktem Tabellenzugriff, Row-Level Security).
4.  **Defense D / A++ (Defense-in-Depth):** Die sequentielle Kombination aller obigen Ebenen.

---

## 5. Quantitative Metriken & Wirtschaftliche Evaluierung

Die H200-Hardware und der Proxmox-Zugang erlauben eine präzise Messung des Sicherheits-Performance-Kosten-Kompromisses (*Trade-off*):

### Sicherheits-Metriken:
*   **Attack Success Rate (ASR):** Prozentsatz erfolgreicher Injections (Datenabfluss / Manipulation) über Promptfoo-Angriffsläufe.
*   **False Positive Rate:** Wie oft blockieren die Schutzmechanismen legitime Nutzeranfragen?

### Performance- & Kosten-Metriken:
*   **Latenz (TTFT & End-to-End):** Wie stark verzögern die Filter und zusätzlichen Guardrail-Aufrufe die Antwortzeit für den Endnutzer?
*   **Energieverbrauch (Watt):** Abfrage des GPU-Verbrauchs über `nvidia-smi` während der Angriffs- und Testläufe zur Berechnung der verbrauchten Wattstunden (Wh) pro Anfrage.
*   **Wirtschaftlichkeit (Kosten):**
    *   Kalkulation der Stromkosten pro 1.000 Abfragen basierend auf dem Rechenzentrums-Tarif.
    *   Vergleich der Gesamtbetriebskosten (TCO) des lokalen H200-Hostings gegenüber Cloud-APIs (z. B. OpenAI/Google APIs) unter Berücksichtigung von Sicherheitsrisiken.