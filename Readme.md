# PromptBreaker BR

Ferramenta de **Red Team para Inteligência Artificial**  testa chatbots e
agentes construídos sobre LLMs quanto a vulnerabilidades da **OWASP Top 10
for LLM Applications**:

- **LLM01** — Prompt Injection (direta e indireta)
- **LLM02** — Vazamento de Informação Sensível
- **LLM06** — Agência Excessiva (Excessive Agency)


## ⚠️ Aviso legal

Use **somente** em chatbots/agentes que você desenvolveu ou administra, ou
com **autorização explícita e por escrito** do responsável pelo sistema.
Uso não autorizado contra sistemas de terceiros pode se enquadrar na
**Lei 12.737/2012** e violar a **LGPD (Lei 13.709/2018)** caso dados
pessoais sejam expostos. O autor não se responsabiliza por uso indevido.

## Instalação

```bash
pip install requests colorama --break-system-packages
```

## Uso — Modo demonstração (sem API, sem custo)

Mostra o problema (modelo vulnerável):
```bash
python3 main.py --demo -v
```

Mostra a defesa funcionando (modelo com guardrails):
```bash
python3 main.py --demo --demo-endurecido -v
```

## Uso — Contra um alvo real

Funciona com qualquer API compatível com o formato de chat da OpenAI
(inclui proxies locais, LM Studio, Ollama com wrapper, etc.):

```bash
export PROMPTBREAKER_API_KEY="sua_chave_aqui"
python3 promptbreaker_br.py --url https://api.seuservico.com/v1/chat/completions \
    --model nome-do-modelo \
    --output relatorio.md \
    -v
```

**Nunca passe sua API key direto na linha de comando** — a ferramenta lê
de uma variável de ambiente (`PROMPTBREAKER_API_KEY` por padrão, ou defina
outro nome com `--api-key-env`).

## Opções

| Flag | Descrição |
|---|---|
| `--url` | Endpoint do chat a ser testado |
| `--model` | Nome do modelo (default: `gpt-3.5-turbo`) |
| `--api-key-env` | Variável de ambiente com a API key |
| `--demo` | Roda em modo demonstração local, sem API real |
| `--demo-endurecido` | No modo demo, simula um modelo com guardrails |
| `--output` | Caminho do relatório em Markdown |
| `--delay` | Segundos entre requisições (default: 1.0) |
| `-v / --verbose` | Mostra a resposta completa de cada teste |
| `--sim-confirmacao` | Pula a confirmação interativa (scripts/CI) |

## Como funciona

Cada teste envia um prompt adversário conhecido e compara a resposta
contra dois conjuntos de palavras-chave: indicadores de **falha** (o
modelo "caiu" no ataque) e indicadores de **resistência** (recusa
apropriada). Quando nenhum dos dois aparece, o teste é marcado como
`REVISAR` para análise manual — a ferramenta é um ponto de partida,
não um veredito automático definitivo.

## Roadmap (ideias pra próxima versão)

- Suporte a testes multi-turno (ataques tipo "Crescendo")
- Exportar relatório também em JSON
- Testes específicos para agentes com ferramentas (tool-calling)
