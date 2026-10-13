# Projeto 5 — File Integrity Monitor em Python

Um monitor de integridade de ficheiros em Python para verificar alterações inesperadas em diretórios críticos.

## Objetivo

O programa cria uma baseline com hashes SHA-256 dos ficheiros monitorizados e, em seguida, compara o estado atual com a referência original. Caso haja ficheiros:

- adicionados
- removidos
- modificados

é emitido um alerta com data, hora e nome do ficheiro afetado.

## Stack

- Python 3
- hashlib
- pathlib
- json
- logging

## Estrutura do projeto

```text
file_integrity_monitor/
├── main.py
├── baseline.json
├── events.log
├── monitored/
│   └── (ficheiros a vigiar)
├── README.md
└── .gitignore
```

## Como usar

### 1) Criar a baseline

```bash
python3 main.py init
```

### 2) Verificar alterações

```bash
python3 main.py check
```

### 3) Monitorização contínua

```bash
python3 main.py watch --interval 5
```

### 4) Forçar a recriação da baseline

```bash
python3 main.py init --force
```

## Exemplo prático

Cria ficheiros de teste:

```bash
mkdir -p monitored
printf "servidor de teste\n" > monitored/server.txt
printf "porta ssh: 22\n" > monitored/config.txt
```

Cria a baseline:

```bash
python3 main.py init
```

Modifica um ficheiro:

```bash
printf "porta ssh: 2222\n" > monitored/config.txt
python3 main.py check
```

Resultado esperado:

```text
[ALERT] Alterações detetadas:
  ~ config.txt
```

## Segurança e boas práticas

- A baseline deve ficar fora da pasta monitorizada.
- O ficheiro de log deve ser protegido por permissões adequadas.
- Em ambientes profissionais, a baseline pode ser armazenada num sistema seguro ou assinada digitalmente.
- A deteção de hash confirma alteração de conteúdo, mas não identifica por si só a causa da mudança.

## Limitações

- Se alguém modificar também a própria baseline, a deteção pode falhar.
- Ficheiros muito grandes continuam a funcionar, mas o cálculo de hash consome CPU e I/O.
- O script é ideal para monitorização local e laboratórios de cibersegurança.

## Autor

0xander
