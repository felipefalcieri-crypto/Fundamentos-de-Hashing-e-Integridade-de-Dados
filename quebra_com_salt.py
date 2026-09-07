"""
quebra_com_salt.py

Demonstra, para fins didáticos, como o uso de salt torna o ataque de
dicionário muito mais custoso: como cada hash usa um salt (potencialmente)
diferente, não é mais possível reutilizar uma única tabela pré-computada
hash->senha para todos os alvos. Cada salt distinto exige recalcular o
hash de cada senha do dicionário.

Uso:
    python quebra_com_salt.py hashes_com_salt.txt senhas_comuns.txt

Formato de hashes_com_salt.txt (um por linha):
    salt_hex:hash_hex

Regras seguidas:
    - hashlib é usado apenas para o cálculo unitário do SHA-256 de cada
      candidato (salt + senha).
    - Toda a lógica de agrupamento por salt, pré-computação e busca foi
      implementada manualmente.

Desafio técnico (bônus) implementado:
    - Se o mesmo salt aparece em múltiplos hashes do arquivo de entrada,
      o hash de cada senha do dicionário para aquele salt é calculado
      apenas UMA vez (agrupamento por salt + tabela de busca por salt).
"""

import sys
import hashlib


def carregar_lista_de_linhas(caminho_arquivo):
    """
    Lê um arquivo texto e devolve uma lista com uma entrada por linha,
    sem espaços em branco nem linhas vazias. Usada tanto para o dicionário
    de senhas quanto (indiretamente) para o arquivo de hashes-alvo.
    """
    linhas = []
    with open(caminho_arquivo, "r", encoding="utf-8", errors="ignore") as f:
        for linha in f:
            linha = linha.strip()
            if linha:
                linhas.append(linha)
    return linhas


def carregar_alvos_salt_hash(caminho_arquivo):
    """
    Lê o arquivo no formato salt_hex:hash_hex e retorna uma lista de
    tuplas (linha_original, salt_hex, hash_hex).

    Guardamos a "linha_original" também porque, na hora de imprimir o
    resultado, queremos mostrar o salt/hash exatamente como veio do
    arquivo do cliente (sem alterações de maiúscula/minúscula, por exemplo).
    """
    alvos = []
    for numero_linha, linha in enumerate(carregar_lista_de_linhas(caminho_arquivo), start=1):
        if ":" not in linha:
            print(f"[AVISO] Linha {numero_linha} fora do formato esperado, ignorando.", file=sys.stderr)
            continue
        # split(":", 1) divide a linha em no máximo 2 partes, a partir da
        # esquerda: tudo antes do primeiro ":" vira o salt, o resto vira o hash.
        salt_hex, hash_hex = linha.split(":", 1)
        # .lower() normaliza para minúsculas, para que a comparação de
        # hashes não falhe por causa de diferenças de maiúscula/minúscula.
        alvos.append((linha, salt_hex.strip().lower(), hash_hex.strip().lower()))
    return alvos


def agrupar_alvos_por_salt(alvos):
    """
    Agrupa os alvos (linha, salt, hash) por salt, para permitir a
    pré-computação: {salt_hex: [(linha_original, hash_hex), ...]}

    Essa é a etapa central do desafio bônus: em vez de tratar cada linha
    do arquivo isoladamente, juntamos numa mesma "gaveta" (lista) todos os
    hashes que compartilham o mesmo salt. Assim, na hora de testar as
    senhas do dicionário, fazemos isso uma única vez por gaveta (por salt),
    em vez de uma vez por hash.
    """
    grupos_por_salt = {}
    for linha_original, salt_hex, hash_hex in alvos:
        if salt_hex not in grupos_por_salt:
            grupos_por_salt[salt_hex] = []
        grupos_por_salt[salt_hex].append((linha_original, hash_hex))
    return grupos_por_salt


def calcular_hash_salt_senha(salt_bytes, senha_str):
    """
    Calcula SHA-256(salt + senha). hashlib usado apenas para o cálculo
    unitário — a lógica de "para quais senhas eu calculo isso" é toda
    manual, feita nas funções abaixo.
    """
    hasher = hashlib.sha256()
    hasher.update(salt_bytes + senha_str.encode("utf-8"))
    return hasher.hexdigest()


def construir_tabela_para_salt(salt_hex, lista_senhas):
    """
    Para um salt específico, pré-computa o hash de CADA senha do
    dicionário uma única vez, retornando um dicionário
    {hash_hex: senha}. Essa tabela pode então ser reutilizada para
    todos os hashes-alvo que compartilham o mesmo salt.

    Note que esta função é chamada UMA vez por salt distinto (não uma vez
    por hash-alvo) — é isso que evita o desperdício de recalcular o
    dicionário inteiro repetidamente quando várias contas compartilham
    o mesmo salt.
    """
    # bytes.fromhex() converte o salt (guardado como texto hexadecimal no
    # arquivo) de volta para a sequência de bytes original.
    salt_bytes = bytes.fromhex(salt_hex)
    tabela = {}
    for senha in lista_senhas:
        hash_calculado = calcular_hash_salt_senha(salt_bytes, senha)
        if hash_calculado not in tabela:
            tabela[hash_calculado] = senha
    return tabela


def quebrar_hashes_com_salt(caminho_hashes_alvo, caminho_dicionario):
    """
    Função principal: orquestra a leitura dos arquivos, o agrupamento por
    salt, a pré-computação por grupo e a impressão dos resultados.
    """
    lista_senhas = carregar_lista_de_linhas(caminho_dicionario)
    alvos = carregar_alvos_salt_hash(caminho_hashes_alvo)
    # Agrupa os hashes por salt ANTES de começar a testar qualquer senha.
    grupos_por_salt = agrupar_alvos_por_salt(alvos)

    total_alvos = len(alvos)
    total_encontrados = 0
    salts_distintos = len(grupos_por_salt)

    print(f"[INFO] {total_alvos} hash(es) alvo, agrupados em {salts_distintos} salt(s) distinto(s).",
          file=sys.stderr)

    # .items() percorre o dicionário devolvendo pares (chave, valor):
    # aqui, cada "chave" é um salt, e cada "valor" é a lista de hashes
    # que usam aquele salt.
    for salt_hex, lista_de_hashes_para_este_salt in grupos_por_salt.items():
        # A tabela é construída UMA vez por salt (fora do loop de baixo),
        # mesmo que existam vários hashes usando esse mesmo salt.
        tabela_hash_para_senha = construir_tabela_para_salt(salt_hex, lista_senhas)

        # Agora sim, para cada hash daquele grupo, é só CONSULTAR a
        # tabela já pronta — sem recalcular nada de novo.
        for linha_original, hash_hex in lista_de_hashes_para_este_salt:
            senha_encontrada = tabela_hash_para_senha.get(hash_hex)
            if senha_encontrada is not None:
                print(f"{salt_hex}:{hash_hex} -> {senha_encontrada}")
                total_encontrados += 1
            else:
                print(f"{salt_hex}:{hash_hex} -> NAO_ENCONTRADA")

    print(f"\n[RESUMO] {total_encontrados}/{total_alvos} hash(es) quebrado(s).", file=sys.stderr)


def main():
    """
    Ponto de entrada: valida os argumentos da linha de comando e chama a
    função principal.
    """
    if len(sys.argv) != 3:
        print(f"Uso: python {sys.argv[0]} hashes_com_salt.txt senhas_comuns.txt")
        sys.exit(1)

    caminho_hashes_alvo = sys.argv[1]
    caminho_dicionario = sys.argv[2]
    quebrar_hashes_com_salt(caminho_hashes_alvo, caminho_dicionario)


if __name__ == "__main__":
    main()
