"""
quebra_sem_salt.py

Demonstra, para fins didáticos, por que hashes SHA-256 SEM salt são
vulneráveis a um ataque de dicionário simples: como o hash de uma mesma
senha é sempre idêntico, basta pré-calcular o hash de cada palavra de um
dicionário e comparar com os hashes fornecidos.

Uso:
    python quebra_sem_salt.py hashes_sem_salt.txt senhas_comuns.txt

Regras seguidas:
    - hashlib é usado apenas para o cálculo unitário do SHA-256 de cada
      candidato de senha do dicionário.
    - A lógica de carregamento do dicionário, geração dos hashes candidatos
      e comparação/busca foi implementada manualmente (sem bibliotecas de
      quebra de senha prontas).
"""

import sys
import hashlib


def carregar_lista_de_linhas(caminho_arquivo):
    """
    Lê um arquivo texto e retorna uma lista com uma entrada por linha,
    removendo espaços em branco e linhas vazias.

    Essa função é genérica: é usada tanto para ler o dicionário de senhas
    (senhas_comuns.txt) quanto para ler o arquivo de hashes-alvo
    (hashes_sem_salt.txt), já que os dois têm o mesmo formato básico
    (uma informação por linha).
    """
    linhas = []
    # "with open(...)" garante que o arquivo será fechado automaticamente
    # no final, mesmo que ocorra algum erro durante a leitura.
    with open(caminho_arquivo, "r", encoding="utf-8", errors="ignore") as f:
        # Percorrer o arquivo linha por linha (não carrega tudo de uma vez
        # em uma única string, o que seria menos eficiente para arquivos grandes).
        for linha in f:
            # .strip() remove espaços, tabs e a quebra de linha ("\n") do
            # início e do fim do texto.
            linha = linha.strip()
            # Ignora linhas em branco (por exemplo, uma linha vazia no
            # final do arquivo).
            if linha:
                linhas.append(linha)
    return linhas


def construir_tabela_dicionario(lista_senhas):
    """
    Constrói manualmente um "dicionário reverso": hash_sha256(senha) -> senha,
    calculando o SHA-256 de cada senha candidata uma única vez.

    Isso evita recalcular o hash de cada senha do dicionário para cada
    hash-alvo (pré-computação), o que é muito mais eficiente do que fazer
    um laço aninhado (para cada hash-alvo, para cada senha).

    Exemplo de ideia: se o dicionário tem 1.000 senhas e o cliente enviou
    500 hashes, um laço aninhado faria 1.000 x 500 = 500.000 cálculos de
    hash. Com esta pré-computação, fazemos apenas 1.000 cálculos (um por
    senha do dicionário) e depois cada busca na tabela é praticamente
    instantânea.
    """
    tabela = {}  # dicionário Python vazio: {hash: senha}

    for senha in lista_senhas:
        # .encode("utf-8") converte o texto (str) em bytes, porque a
        # função de hash trabalha sobre sequências de bytes, não sobre texto.
        # hashlib.sha256(...) é usado APENAS aqui, para calcular o hash de
        # UMA senha por vez — não existe nenhuma função pronta que já
        # "quebre" a senha sozinha; toda a lógica de busca é manual.
        hash_calculado = hashlib.sha256(senha.encode("utf-8")).hexdigest()

        # Em caso de colisão (duas senhas diferentes com o mesmo hash —
        # praticamente impossível no SHA-256), mantemos a primeira ocorrência,
        # ou seja, não sobrescrevemos uma entrada já existente na tabela.
        if hash_calculado not in tabela:
            tabela[hash_calculado] = senha

    return tabela


def quebrar_hashes(caminho_hashes_alvo, caminho_dicionario):
    """
    Função principal do ataque: recebe o caminho do arquivo de hashes do
    cliente e o caminho do dicionário de senhas, e imprime na tela o
    resultado de cada tentativa de quebra.
    """
    # 1) Carrega todas as senhas candidatas do dicionário fornecido.
    lista_senhas = carregar_lista_de_linhas(caminho_dicionario)

    # 2) Pré-computa a tabela hash -> senha, UMA vez, para todo o dicionário.
    tabela_hash_para_senha = construir_tabela_dicionario(lista_senhas)

    # 3) Carrega a lista de hashes que o cliente quer testar.
    hashes_alvo = carregar_lista_de_linhas(caminho_hashes_alvo)

    encontrados = 0  # contador de quantos hashes foram quebrados com sucesso

    # 4) Para cada hash do cliente, apenas CONSULTA a tabela pré-computada
    #    (não recalcula nada aqui — é por isso que o processo é rápido).
    for hash_alvo in hashes_alvo:
        # .lower() normaliza para minúsculas, pois hexdigest() do Python
        # sempre gera letras minúsculas, mas o arquivo do cliente pode
        # eventualmente conter hashes em maiúsculas.
        hash_normalizado = hash_alvo.strip().lower()

        # dicionario.get(chave) devolve o valor se a chave existir, ou
        # None se não existir — evita ter que testar "if chave in dicionario"
        # e depois acessar de novo (mais eficiente).
        senha_encontrada = tabela_hash_para_senha.get(hash_normalizado)

        if senha_encontrada is not None:
            print(f"{hash_alvo}:{senha_encontrada}")
            encontrados += 1
        else:
            print(f"{hash_alvo}:NAO_ENCONTRADA")

    # O resumo final é enviado para sys.stderr (saída de erro) em vez de
    # print() comum (que vai para stdout). Isso é só uma boa prática: assim,
    # se alguém quiser redirecionar apenas os resultados "hash:senha" para
    # um arquivo, o resumo não entra junto no meio dos dados.
    print(f"\n[RESUMO] {encontrados}/{len(hashes_alvo)} hash(es) quebrado(s) com o dicionário fornecido.",
          file=sys.stderr)


def main():
    """
    Ponto de entrada do script: lê os argumentos passados na linha de
    comando e chama a função principal.
    """
    # sys.argv é a lista de argumentos digitados no terminal.
    # sys.argv[0] é sempre o nome do próprio script.
    # Esperamos exatamente 3 posições: [script, hashes_alvo, dicionario].
    if len(sys.argv) != 3:
        print(f"Uso: python {sys.argv[0]} hashes_sem_salt.txt senhas_comuns.txt")
        sys.exit(1)  # encerra o programa com código de erro 1

    caminho_hashes_alvo = sys.argv[1]
    caminho_dicionario = sys.argv[2]
    quebrar_hashes(caminho_hashes_alvo, caminho_dicionario)


# Esse "if" garante que main() só roda quando o arquivo é executado
# diretamente (python quebra_sem_salt.py ...), e não quando é importado
# como módulo dentro de outro script.
if __name__ == "__main__":
    main()
