# CI Framework com Segurança Integrada

Framework GitHub Actions reutilizável para pipelines de CI que incluem **build, testes e verificações de segurança** (SAST, SCA, segredos e IaC) para Node.js, Python, Java e Terraform.

## ✨ Características

- **Pipeline completa** – build, testes, análise estática, análise de dependências, verificação de segredos.
- **Reutilizável** – um único workflow chamado por todos os repositórios.
- **Segurança nativa** – Semgrep (SAST) + Trivy (SCA/IaC).
- **Gate inteligente** – falha apenas em CRITICAL/HIGH (configurável). Bypass via label `security-bypass`.
- **Artefatos** – SARIF para cada etapa, relatório consolidado em Markdown/JSON.

## 🚀 Uso

1. Faça o fork deste repositório `ci-framework` para sua organização.
2. Em cada repositório alvo, crie `.github/workflows/ci.yml` conforme exemplo acima.
3. Configure o segredo `SEMGREP_APP_TOKEN` nos repositórios alvo (opcional, mas recomendado).
4. Execute o pipeline via PR ou manualmente via `workflow_dispatch` no `ci-framework`.

## 🧪 Exemplo de execução local (script gate)

```bash
cp .env.example .env
export $(cat .env | xargs)
python scripts/gate.py sample.sarif