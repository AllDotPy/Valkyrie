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

---

## 🛡️ **Why Valkyrie?**

| Feature | Description |
| :--- | :--- |
| **🔌 Seamless Integration** | Native integration with GitHub Actions, GitLab CI, and more. Results are posted directly in the PR. |
| **🏗️ Clean & Extensible Architecture** | Modern, strongly-typed Python code, easy to contribute to and extend. |
| **🧩 Crowdsourced Rules** | The value comes from the community. Share rules for any service or tool. |
| **⚡ Fast & Preventive** | Blazing-fast scans designed to keep pace with development, not slow it down. |

## 🚀 **Get Started in 2 Minutes**

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

## 🤝 Contributing

We welcome contributions from the community! Please see the CONTRIBUTING.md guide for more information.

---

**Valkyrie: Security, forged by the community.**

<br>
<p align = 'center'>
    <img src='alldotpy.png?raw=true' height = '60'></img>
</p>
<p align = 'center'>Made with ❤️ By AllDotPy</p>
