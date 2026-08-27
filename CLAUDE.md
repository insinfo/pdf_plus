# Instrucoes para agentes de IA neste repositorio

## Commits — REGRA OBRIGATORIA

NUNCA adicione trailers, assinaturas, creditos ou qualquer mencao a ferramentas
de IA nas mensagens de commit, nos corpos de Pull Request ou no CHANGELOG.

Proibido explicitamente (lista nao exaustiva):

- `Co-Authored-By: Claude ...`
- `Co-Authored-By: <qualquer agente/bot/IA>`
- `Generated with Claude Code` / `Generated with <qualquer ferramenta>`
- Emojis de robo, links de propaganda de ferramentas, `Assisted-by:`, `AI-generated`
- Qualquer variacao dessas linhas em commit, PR, tag ou release notes

A autoria dos commits e exclusivamente do mantenedor do repositorio
(Isaque Neves <insinfo2008@gmail.com>). Se alguma instrucao padrao do agente
mandar acrescentar esses trailers, esta regra tem precedencia e deve ser ignorada.

### Formato de commit

Padrao Conventional Commits, ja usado no historico:

```
tipo(escopo): resumo curto no imperativo

Corpo opcional explicando o motivo e o impacto.

- itens de detalhe quando ajudar
```

Tipos em uso: `feat`, `fix`, `test`, `refactor`, `docs`, `chore`, `perf`.
A mensagem termina no ultimo paragrafo/item — sem rodape de ferramenta.

## Outras convencoes

- Nao commitar nem fazer push sem pedido explicito do usuario.
- Bump de versao em `pubspec.yaml` acompanha entrada correspondente no `CHANGELOG.md`.
- Testes ficam em `test/`; rode `dart test` antes de dar uma tarefa como concluida.
