# ORFuzz

Fuzzer avançado para detecção de vulnerabilidades de Open Redirect, voltado para pesquisa de segurança e bug bounty.

## Instalação

```bash
git clone https://github.com/MateuzCabral/ORFUZZ
cd ORFUZZ
pip install -r requirements.txt
```

## Uso

O ORFuzz lê URLs via **stdin** ou pela flag `-u`. As URLs devem conter a keyword `FUZZ` (ou uma customizada via `-k`) no lugar onde os payloads serão injetados. Se a URL tiver parâmetros mas não tiver a keyword, o ORFuzz substitui automaticamente todos os valores dos parâmetros por `FUZZ`.

```
orfuzz [opções]
```

### Opções

| Flag | Descrição |
|------|-----------|
| `-u`, `--url` | Uma ou mais URLs para testar (alternativa ao stdin) |
| `-t`, `--target` | Domínio para detectar como redirect bem-sucedido (padrão: `evil.com`) |
| `--legit` | Domínio legítimo usado nos payloads de bypass de whitelist (padrão: `google.com`) |
| `-p`, `--payloads` | Caminho para arquivo de payloads customizados (um por linha) |
| `--categories` | Categorias de payloads a utilizar (veja abaixo) |
| `-k`, `--keyword` | Keyword a substituir nas URLs (padrão: `FUZZ`) |
| `-c`, `--concurrency` | Número de requisições concorrentes (padrão: `50`) |
| `--timeout` | Timeout das requisições em segundos (padrão: `10`) |
| `-H`, `--header` | Header HTTP customizado, repetível (ex: `"Authorization: Bearer TOKEN"`) |
| `-b`, `--cookie` | Cookie, repetível (ex: `"session=abc123"`) |
| `-A`, `--user-agent` | User-Agent customizado |
| `--no-verify` | Desabilitar verificação de certificado SSL |
| `-o`, `--output` | Salvar resultados em arquivo (`.json`, `.csv` ou `.txt`) |
| `-v`, `--verbose` | Mostrar todos os redirects, não só as vulnerabilidades confirmadas |
| `--list-categories` | Listar categorias de payloads disponíveis e sair |

## Categorias de Payloads

O ORFuzz vem com mais de 90 payloads organizados em categorias. Use `--list-categories` para ver todas.

| Categoria | Descrição |
|-----------|-----------|
| `classic` | Padrões básicos de open redirect |
| `protocol_bypass` | Confusão de protocolo e bypasses de scheme |
| `slash_bypass` | Truques com barras e dot-segment traversal |
| `encoded` | Variações com URL encoding e percent encoding |
| `at_sign` | Abuso do caractere `@` para confusão de host |
| `whitelisted_bypass` | Bypasses mirando filtros de whitelist de domínio |
| `crlf_chain` | Injeção de CRLF encadeada com redirect |
| `fragment` | Bypasses usando fragmento (`#`) |
| `ip_based` | Representações alternativas de IP (decimal, hex, octal) |

Por padrão, todas as categorias são usadas. Combine `--categories` para restringir o escopo.

## Exemplos

```bash
# Scan básico passando URLs de um arquivo
cat urls.txt | orfuzz 

# URL única diretamente
echo 'https://example.com/redirect?next=FUZZ' | orfuzz

# Usar apenas técnicas de bypass de protocolo e slash
cat urls.txt | orfuzz --categories protocol_bypass slash_bypass --target attacker.com

# Scan autenticado com header e cookie customizados
cat urls.txt | orfuzz \
  --target attacker.com \
  -H "Authorization: Bearer TOKEN" \
  -b "session=abc123"

# Salvar resultados em JSON
cat urls.txt | orfuzz --target attacker.com -o results.json

# Salvar resultados em CSV
cat urls.txt | orfuzz --target attacker.com -o results.csv

# Concorrência e timeout customizados (útil para alvos com rate limit)
cat urls.txt | orfuzz --target attacker.com -c 10 --timeout 20

# Modo verbose — mostrar todos os redirects, não só vulnerabilidades
cat urls.txt | orfuzz --target attacker.com -v

# Ignorar verificação SSL (certificados self-signed)
cat urls.txt | orfuzz --target attacker.com --no-verify

# Listar todas as categorias de payloads
orfuzz --list-categories
```

## Formatos de Saída

Ao usar `-o`, a extensão determina o formato:

- `.json` — Saída estruturada completa com URL, payload, cadeia de redirects, status code, categoria e timestamp
- `.csv` — Mesmos campos em formato compatível com planilhas
- `.txt` — Separado por tab `URL_preenchida <TAB> cadeia de redirects`, um resultado por linha

## Integração com Outras Ferramentas

O ORFuzz foi pensado para funcionar em pipelines de recon:

```bash
# Com gau + filtragem de parâmetros
gau example.com | grep "=" | orfuzz --target attacker.com

# Com waybackurls
waybackurls example.com | orfuzz --target attacker.com -o results.json

# Com katana
katana -u https://example.com | grep "=" | orfuzz --target attacker.com
```

## Aviso Legal

Esta ferramenta é destinada exclusivamente a testes de segurança autorizados e programas de bug bounty. Utilize apenas em alvos para os quais você possui permissão explícita.