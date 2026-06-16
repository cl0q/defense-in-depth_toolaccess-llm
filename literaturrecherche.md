# Literaturrecherche: Sicherheit von LLMs mit Datenbankzugriff

Diese Datei enthält alle recherchierten wissenschaftlichen Quellen für deine Bachelorarbeit. Insgesamt wurden **11 Quellen** aufbereitet.

---

### 1. From Prompt Injections to SQL Injection Attacks: How Protected is Your LLM-Integrated Web Application?
* **Autoren:** Rodrigo Pedro, Daniel Castro, Paulo Carreira, Nuno Santos
* **Link:** [arXiv:2308.01990](https://arxiv.org/abs/2308.01990) (Präsentiert auf der ICSE 2025)
* **Worum es geht:** Die Arbeit untersucht, wie Prompt Injections in LangChain-basierten Anwendungen zu SQL-Injections (P2SQL) führen können, evaluiert dies über 7 verschiedene LLMs und schlägt 4 Abwehrmechanismen vor.
* **Warum es hilft:** Es ist die wichtigste Grundlage für deine Bedrohungsanalyse und zeigt, dass die Übersetzung von natürlicher Sprache in SQL standardmäßig extrem unsicher ist.

### 2. On the Security Vulnerabilities of Text-to-SQL Models
* **Autoren:** Xutan Peng, Yipeng Zhang, Jingfeng Yang, Mark Stevenson
* **Link:** [arXiv:2211.15363](https://arxiv.org/abs/2211.15363) (Best Paper Candidate bei ISSRE 2023)
* **Worum es geht:** Die Autoren zeigen empirisch an sechs kommerziellen Systemen und vier Open-Source-LLMs, dass Text-to-SQL-Komponenten gezielt manipuliert werden können, um Schadcode in Datenbanken auszuführen (Datenabfluss & DoS).  
* **Warum es hilft:** Es belegt wissenschaftlich, dass Text-to-SQL-Modelle in realen Anwendungen ein kritisches Einfallstor für Angreifer darstellen und ungeschützt direkte Sicherheitsrisiken bergen.

### 3. Unmasking Database Vulnerabilities: Zero-Knowledge Schema Inference Attacks in Text-to-SQL Systems
* **Autoren:** Đorđe Klisura, Anthony Rios
* **Link:** [arXiv:2406.14545](https://arxiv.org/abs/2406.14545) (NAACL 2025 Findings)
* **Worum es geht:** Es wird ein Framework vorgestellt, mit dem Angreifer ohne Vorkenntnisse (Zero-Knowledge) das zugrundeliegende Datenbankschema (Tabellen, Spalten, Datentypen) eines Text-to-SQL-Systems ausspähen können.
* **Warum es hilft:** Diese Arbeit liefert die wissenschaftliche Begründung für deine datenbankseitigen Schutzmaßnahmen (Defense C: Views und restriktive Schemata), um Schema-Leckagen zu verhindern.

### 4. Benchmarking LLAMA Model Security Against OWASP Top 10 For LLM Applications
* **Autoren:** Nourin Shahin, Izzat Alsmadi
* **Link:** [arXiv:2601.19970](https://arxiv.org/abs/2601.19970) (Publiziert im Januar 2026)
* **Worum es geht:** Die Studie evaluiert verschiedene Llama-Modelle und Llama-Guard-Varianten gegen das OWASP Top 10 Framework und misst dabei sowohl die Erkennungsgenauigkeit als auch den Latenz-Overhead.
* **Warum es hilft:** Es liefert dir konkrete Vergleichswerte für deine Forschungsfrage FF2 (Kosten-Trade-off). Du kannst deine gemessenen Latenzen direkt mit den dort dokumentierten Latenzen (z.B. Llama-Guard-3-1B) vergleichen.

### 5. When Scanners Lie: Evaluator Instability in LLM Red-Teaming
* **Autoren:** Lidor Erez, Omer Hofman, Tamir Nizri, Roman Vainshtein
* **Link:** [arXiv:2603.14633](https://arxiv.org/abs/2603.14633) (März 2026)
* **Worum es geht:** Das Papier zeigt auf, dass automatisierte LLM-Sicherheits-Scanner (wie Garak) stark schwankende ASR-Ergebnisse liefern, weil die LLM-basierten Evaluatoren, die den Erfolg eines Angriffs bewerten, instabil sind.
* **Warum es hilft:** Dies ist die perfekte methodische Rechtfertigung für dein *deterministisches Orakel* (DB-Logs, State-Diffs und Canary-Werte). Du zeigst damit, dass du eine bekannte Schwachstelle aktueller Testverfahren löst.

### 6. Architecting Secure AI Agents: Perspectives on System-Level Defenses Against Indirect Prompt Injection Attacks
* **Autoren:** Chong Xiang, Drew Zagieboylo, Shaona Ghosh, Sanjay Kariyappa, Kai Greshake, Hanshen Xiao, Chaowei Xiao, G. Edward Suh
* **Link:** [arXiv:2603.30016](https://arxiv.org/abs/2603.30016) (März 2026)
* **Worum es geht:** Ein Positionspapier, das argumentiert, dass reine LLM-Guardrails unzureichend sind und robuste KI-Agenten systemseitige, architektonische Schutzmaßnahmen (wie strikte Daten-/Instruktionstrennung) benötigen.
* **Warum es hilft:** Es stützt deine Forschungsfrage FF3 (Architektur vs. Guardrails) und belegt, warum datenbankseitige Härtung (Defense C) essenziell für Enterprise-Systeme ist.

### 7. Enhancing Accuracy and Maintainability in Nuclear Plant Data Retrieval: A Function-Calling LLM Approach Over NL-to-SQL
* **Autoren:** Mishca de Costa, Muhammad Anwar, Dave Mercier, Mark Randall, Issam Hammad
* **Link:** [arXiv:2506.08757](https://arxiv.org/abs/2506.08757) (Juni 2025)
* **Worum es geht:** Die Arbeit vergleicht direkte Text-to-SQL-Systeme mit einem sichereren Function-Calling-Ansatz (wo das LLM nur validierte, vordefinierte Datenbankfunktionen aufruft) in einer sicherheitskritischen Umgebung.
* **Warum es hilft:** Es dient als exzellenter Beleg für deine architektonische Abwägung (FF3), da es zeigt, wie durch Einschränkung der Handlungsfähigkeit (Excessive Agency / LLM06) Risiken minimiert werden.

### 8. Great, Now Write an Article About That: The Crescendo Multi-Turn LLM Jailbreak Attack
* **Autoren:** Mark Russinovich, Ahmed Salem, Ronen Eldan (Microsoft)
* **Link:** [arXiv:2404.01833](https://arxiv.org/abs/2404.01833) (USENIX Security 2025)
* **Worum es geht:** Stellt den Crescendo-Angriff vor, einen systematischen, mehrstufigen Jailbreak, bei dem der Angreifer das Modell Schritt für Schritt zu verbotenen Aktionen verleitet.
* **Warum es hilft:** Da du Crescendo über Promptfoo als einen deiner Hauptangriffsvektoren nutzt, ist dies die offizielle theoretische Referenz dafür.

### 9. Tree of Attacks: Jailbreaking Black-Box LLMs Automatically
* **Autoren:** Anay Mehrotra, Manolis Zampetakis, Paul Kassianik, Blaine Nelson, Hyrum Anderson, Yaron Singer, Amin Karbasi
* **Link:** [arXiv:2312.02119](https://arxiv.org/abs/2312.02119) (NeurIPS 2024)
* **Worum es geht:** Beschreibt TAP (Tree of Attacks with Pruning), einen automatisierten Blackbox-Angriff, der mittels eines Angreifer-LLMs systematisch Prompts verfeinert und unpromising Pfade verwirft.
* **Warum es hilft:** Es ist die wissenschaftliche Quelle für den TAP-Algorithmus, den du ebenfalls in deiner Evaluierungs-Pipeline einsetzt.

### 10. garak: LLM vulnerability scanner
* **Autoren:** Leon Derczynski, Erick Galinkin, Jeffrey Martin, Subho Majumdar, Nanna Inie
* **Link:** [arXiv:2406.11039](https://arxiv.org/abs/2406.11039) (Juni 2024)
* **Worum es geht:** Die offizielle Veröffentlichung zur Einführung des LLM-Vulnerability-Scanners Garak, der bekannte Sicherheitslücken und Jailbreaks scannt.
* **Warum es hilft:** Die Primärquelle zur wissenschaftlichen Zitierung deines Baseline-Scanners Garak.

### 11. Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection
* **Autoren:** Kai Greshake, Sahar Abdelnabi, Shailesh Mishra, Christoph Endres, Thorsten Holz, Mario Fritz
* **Link:** [arXiv:2302.12173](https://arxiv.org/abs/2302.12173) (2023)
* **Worum es geht:** Das wegweisende Grundlagenpapier, das erstmals das Konzept der indirekten Prompt Injection (IPI) vorstellt und demonstriert, wie Angreifer über externe Datenquellen (wie Webseiten oder Datenbanken) die Kontrolle über LLMs erlangen.
* **Warum es hilft:** Dies ist die wichtigste theoretische Säule für deinen Fokus auf indirekte Injektionen über PostgreSQL-Datenbanken (Canarys/Stored Injections).