🚨 New open-source release: `llm-sanitizer`

LLM security is still lagging behind adoption. Prompt injection, hidden instructions in documents, and embedded agent directives are quickly becoming real attack vectors—not theoretical ones.

I’ve been working on a small but focused tool to address this gap:

👉 https://github.com/Warnes-Innovations/llm-sanitizer  
👉 https://pypi.org/project/llm-sanitizer/

**What it does:**

- Detects and classifies embedded LLM instructions in:

    - documents
    - source code
    - web content

- Redacts or neutralizes those instructions before they reach your model

- Runs as:

    - a Python package (importable directly in your pipeline)
    - a CLI tool
    - an MCP-compatible server

Conceptually, it sits as a **pre-processing security layer**—intercepting prompts before they ever hit your LLM.

This is an initial effort to address the growing need for *defense-in-depth* in LLM pipelines, especially given how easy it is to smuggle instructions via seemingly benign inputs (markdown, HTML, comments, etc.).

**`llm-sanitizer` explicitly targets embedded instruction payloads and prompt injection vectors across artifact types**

---

### Why I built this

Most LLM applications today implicitly trust upstream content. That’s a risky assumption.

If your system ingests:

- scraped web pages  
- PDFs / documents  
- code repositories  
- user-uploaded files  

…then you already have a potential prompt injection surface.

---

### What I’d love feedback on

This is an early release (v0.1.0), and I’m actively iterating. I’d especially value input on:

- Detection strategy (regex vs. structural vs. model-assisted)  
- False positive / false negative tradeoffs  
- Integration patterns (pipelines, agents, MCP, etc.)  
- Real-world attack examples I should include  

---

If you’re building in the LLM / agent space, I’d really appreciate you kicking the tires and sharing thoughts—good or bad.

Security here is still an open problem, and the ecosystem needs more experimentation.

---

#LLM #AI #Security #PromptInjection #OpenSource #MLOps