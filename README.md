
<p align="center">
<!--     <a href="https://pypi.org/project/FletXr/">
        <img src="https://img.shields.io/pypi/v/FletXr" alt="PyPI Version" />
    </a> -->
<!--     <a href="https://pepy.tech/project/FletXr">
        <img src="https://static.pepy.tech/badge/FletXr" alt="Downloads" />
    </a> -->
    <a href="LICENSE">
        <img src="https://img.shields.io/badge/License-AGPLv3-blue.svg" alt="License" />
    </a>
    <a href="">
        <img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python" />
    </a>
    <a href="https://github.com/AllDotPy/Valkyrie">
        <img src="https://img.shields.io/github/commit-activity/m/AllDotPy/Valkyrie" alt="GitHub commit activity" />
    </a>
</p>


# Valkyrie
The guardian of your Pull Requests. She decides what gets to merge.

Valkyrie is a robust, strongly-typed, open-source security scanner that integrates directly into your CI/CD pipelines (GitHub Actions, GitLab CI, etc.). Like the mythical Valkyries who chose which warriors were worthy of Valhalla, our tool ruthlessly inspects every Pull Request, allowing only secure code to pass through and merge.

**Stop threats at the gate:**

- 🔒 Secrets & Passwords: API keys, tokens, credentials...

- 📦 Vulnerable Dependencies (SBOM): Known vulnerabilities in your libraries.

- ☁️ Risky IAM Configurations: Overly permissive policies in AWS, GCP, or Azure.

**Our strength? The community of shieldmaidens and shieldmasters.**

Valkyrie's power comes from its crowdsourced rule set. The community continuously creates, shares, and improves scanning rules to cover every cloud service (AWS, GCP, that obscure SaaS) and every framework.

**Ready to join the guard?** Contribute rules, report false positives, improve the engine. Together, we make the open-source ecosystem safer.

> ⚠️ Project Status: Active Development
Valkyrie is currently under heavy development. We're building an industrial-grade security scanner with the community. Join us to shape the future of proactive security!

---

## 🛡️ **Why Valkyrie?**

| Feature | Description |
| :--- | :--- |
| **🔌 Seamless Integration** | Native integration with GitHub Actions, GitLab CI, and more. Results are posted directly in the PR. |
| **🏗️ Clean & Extensible Architecture** | Modern, strongly-typed Python code, easy to contribute to and extend. |
| **🧩 Crowdsourced Rules** | The value comes from the community. Share rules for any service or tool. |
| **⚡ Fast & Preventive** | Blazing-fast scans designed to keep pace with development, not slow it down. |

### ✅ Robustness & Performance (Planned)

- Async scanning with worker limiting
- Robust error handling without interruptions
- Rule caching and optimizations
- Large project support (>10MB per file)

### ✅ Extensibility (Planned)

- Clean plugin system with clear interfaces
- Customizable YAML rules by the community
- Multi-cloud support (AWS, GCP, Azure, etc.)
- Extensible API for new scanners

### ✅ Native CI/CD Integration (Planned)

- Auto-detection of CI environments
- Standard output formats (SARIF, GitLab SAST)
- Automatic PR/MR comments
- Diff-only support for optimized scans

### ✅ Clean Architecture (Planned)

- Strongly typed code (mypy compatible)
- Clear separation of concerns
- Industry-standard patterns (Repository, Plugin, Strategy)

### 🏗️ Current Development Focus

We're currently building the foundational layers:

- Core Scanning Engine - Async, typed, modular
- Plugin System - Extensible security checks
- Rule Repository - Community-driven patterns
- CI Integrations - GitHub Actions first

---

## 🚀 Coming Soon - Planned Features
### 🔍 Multi-Layer Security Scanning

- **Secrets Detection**: API keys, tokens, credentials with crowd-sourced patterns
- **Dependency Scanning**: SBOM generation and vulnerability detection (Vulnera plugin)
- **IAM Configuration**: Risky cloud permissions in AWS, GCP, Azure configurations
- **Custom Rules**: Community-driven detection rules for any service or framework

## 🚀 **Get Started in 2 Minutes (When Available)**

```yaml
# .github/workflows/valkyrie-scan.yml
name: Security Scan with Valkyrie

on: [pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Valkyrie Scan
        uses: valkyrie-scanner/action@v1
        with:
          rules-repo: 'valkyrie-community/rules' # The central community rules repo
```

<!-- ## 📚 **Join the Legend**

We are looking for contributors of all kinds:
- **Python Developers** to work on the core engine.
- **Cloud Experts** (AWS, GCP, Azure, etc.) to write powerful rules.
- **DevOps Engineers** to enhance CI/CD integrations.
- **Technical Writers** to help make Valkyrie accessible to everyone.

Check out our `CONTRIBUTING.md` guide to see how you can help.

**Join the guard and become an open-source security legend.**

--- -->
---

## 📜 License

Valkyrie is licensed under AGPLv3 for open source use. Commercial licenses are available for enterprises that cannot use AGPLv3.

---

## 🤝 Contributing

We welcome contributions from the community! Please see the [CONTRIBUTING.md](CONTRIBUTING.md) guide for more information.

---

**Ready to join the guard?**
Star the repo, open an issue, or submit a PR. Together, we'll build the security guardian every codebase deserves.

**_Valkyrie: Security, forged by the community._**

<br>
<p align = 'center'>
    <img src='alldotpy.png?raw=true' height = '60'></img>
</p>
<p align = 'center'>Made with ❤️ By AllDotPy</p>
