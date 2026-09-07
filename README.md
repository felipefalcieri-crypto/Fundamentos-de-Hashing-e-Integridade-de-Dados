# Fundamentos de Hashing e Integridade de Dados

Projeto de Segurança da Informação com foco em **verificação de integridade de arquivos** e **avaliação técnica da robustez de hashes de senha**, desenvolvido em Python.

## Restrições de implementação seguidas

- `hashlib` é usado **apenas** para o cálculo unitário de um hash SHA-256 — nunca para verificar integridade completa ou quebrar senhas de forma automatizada.
- Nenhuma biblioteca pronta de quebra de senha foi utilizada (`passlib`, `bcrypt` pronto, `hashcat`, `john`).
- Toda a lógica de comparação de hashes, geração de salt e busca em dicionário foi implementada manualmente.

## Estrutura do repositório

| Arquivo | Descrição |
|---|---|
| `verificador_integridade.py` | Calcula o SHA-256 de todos os arquivos de um diretório (recursivamente) e detecta arquivos novos, removidos, modificados ou inalterados entre duas execuções. |
| `quebra_sem_salt.py` | Testa hashes SHA-256 **sem salt** contra um dicionário de senhas comuns. |
| `cadastro_verificacao.py` | Simula um módulo de cadastro/login de usuários usando SHA-256 **com salt** individual por usuário. |
| `quebra_com_salt.py` | Testa hashes **com salt** contra um dicionário, com pré-computação otimizada para salts reutilizados. |
| `senhas_comuns.txt` | Dicionário de senhas comuns usado nos testes de quebra. |
| `dados/`, `hashes*.txt`, `usuarios.txt` | Arquivos de exemplo/saída gerados durante os testes manuais dos scripts. |

### 1. Verificador de integridade

```bash
# Gera o registro inicial de hashes de uma pasta
python verificador_integridade.py ./dados

# Compara o estado atual com o registro salvo
python verificador_integridade.py ./dados --verificar
```

### 2. Quebra de hash sem salt

```bash
python quebra_sem_salt.py hashes_sem_salt.txt senhas_comuns.txt
```

### 3. Cadastro e verificação de usuários (com salt)

```bash
python cadastro_verificacao.py --cadastrar alice senha123
python cadastro_verificacao.py --verificar alice senha123
```

### 4. Quebra de hash com salt

```bash
python quebra_com_salt.py hashes_com_salt.txt senhas_comuns.txt
```

## Principais conceitos demonstrados

- **Leitura em blocos (chunking)** para processar arquivos grandes (>1 GB) sem estourar a memória RAM.
- **Pré-computação de tabelas hash→senha** para acelerar ataques de dicionário.
- **Diferença prática entre hash com e sem salt**: sem salt, uma única tabela pré-computada quebra qualquer conta com aquela senha; com salt, cada conta exige recomputação individual — a menos que salts se repitam, caso em que o agrupamento por salt permite reaproveitar o cálculo.
- **Boas práticas de armazenamento de senha**: salt aleatório com `os.urandom`, nunca armazenar senha em texto claro, e comparação de hash em tempo constante para mitigar ataques de timing.

## Relatório completo

O relatório técnico completo, com fundamentação teórica (funções hash, colisões, SHA-1, salt, tipos de ataque) e evidências de teste de cada script, está disponível em `Relatorio_Seguranca_da_Informacao.docx` / `.pdf`.

## Autoria

Projeto desenvolvido para fins acadêmicos na disciplina de Segurança da Informação.
