#!/usr/bin/env python3
"""
verificador_integridade.py

Ferramenta de verificação de integridade de arquivos usando SHA-256.

Uso:
    python verificador_integridade.py <diretorio>              -> gera hashes.txt
    python verificador_integridade.py <diretorio> --verificar  -> compara estado atual com hashes.txt

Regras seguidas:
    - hashlib é usado APENAS para o cálculo unitário do SHA-256 de cada
      arquivo (não existe nenhuma função pronta de "comparação de integridade"
      sendo chamada).
    - Toda a lógica de varredura de diretórios, comparação de estados e geração
      do relatório foi implementada manualmente.
    - Leitura em blocos (chunks) para suportar arquivos grandes (> 1 GB) sem
      estourar a memória RAM.
"""

import sys
import os
import hashlib

NOME_ARQUIVO_HASHES = "hashes.txt"
TAMANHO_BLOCO = 1024 * 1024  # 1 MiB por leitura, para não carregar o arquivo inteiro na RAM


def calcular_sha256_arquivo(caminho_arquivo):
    """
    Calcula o hash SHA-256 de um único arquivo, lendo-o em blocos (chunks).
    hashlib é utilizado aqui apenas para o cálculo unitário do hash,
    conforme permitido pelo enunciado.

    Por que ler em blocos? Se o arquivo tiver, por exemplo, 5 GB, tentar
    carregá-lo inteiro na memória (com f.read() sem argumento) poderia
    travar o programa ou até o computador. Lendo aos poucos (1 MiB por vez)
    e "alimentando" o hash com cada pedaço, a memória usada fica sempre
    pequena e constante, não importa o tamanho do arquivo.
    """
    # hashlib.sha256() cria um "objeto hash" vazio, que vai sendo
    # atualizado aos poucos — ele guarda o estado interno do cálculo.
    hasher = hashlib.sha256()
    try:
        # "rb" = read binary. Arquivos precisam ser lidos como bytes
        # (não como texto), pois podem conter qualquer tipo de conteúdo
        # (imagens, executáveis, etc.), não só texto.
        with open(caminho_arquivo, "rb") as f:
            while True:
                # Lê no máximo TAMANHO_BLOCO bytes por vez.
                bloco = f.read(TAMANHO_BLOCO)
                # Quando não há mais nada para ler, f.read() devolve
                # um bytes vazio (b""), que é "falso" em um "if", então
                # o loop para aqui.
                if not bloco:
                    break
                # Acrescenta esse pedaço ao cálculo do hash (sem guardar
                # o conteúdo do arquivo inteiro em memória).
                hasher.update(bloco)
    except (PermissionError, FileNotFoundError, OSError) as erro:
        # Se o arquivo não puder ser lido (permissão negada, foi apagado
        # no meio do processo, etc.), avisamos e retornamos None em vez
        # de travar o programa inteiro.
        print(f"[AVISO] Não foi possível ler '{caminho_arquivo}': {erro}", file=sys.stderr)
        return None
    # .hexdigest() transforma o resultado binário do hash em uma string
    # de texto hexadecimal (mais fácil de salvar em arquivo e comparar).
    return hasher.hexdigest()


def listar_arquivos_recursivo(diretorio_raiz):
    """
    Percorre manualmente (recursivamente) o diretório informado e retorna
    uma lista de caminhos relativos de todos os arquivos encontrados,
    incluindo os que estão em subpastas.
    """
    lista_de_arquivos = []
    # os.walk() é a forma padrão do Python de "andar" por uma árvore de
    # pastas. A cada iteração, ele entrega: a pasta atual, a lista de
    # subpastas dentro dela, e a lista de arquivos dentro dela — e repete
    # isso automaticamente para cada subpasta, ou seja, ele já é recursivo.
    for pasta_atual, subpastas, arquivos in os.walk(diretorio_raiz):
        for nome_arquivo in arquivos:
            # Monta o caminho completo (ex: dados/sub/b.txt)
            caminho_completo = os.path.join(pasta_atual, nome_arquivo)
            # Calcula o caminho relativo à pasta raiz que foi passada
            # (ex: se diretorio_raiz = "dados", o resultado é "sub/b.txt",
            # não o caminho completo do computador).
            caminho_relativo = os.path.relpath(caminho_completo, diretorio_raiz)
            # No Windows, os separadores de pasta são "\", mas no
            # hashes.txt queremos sempre "/", para o arquivo ficar igual
            # não importa em qual sistema operacional foi gerado.
            caminho_relativo = caminho_relativo.replace(os.sep, "/")
            lista_de_arquivos.append(caminho_relativo)
    # Ordena a lista para que o hashes.txt sempre saia na mesma ordem
    # (facilita comparar o arquivo manualmente, se precisar).
    lista_de_arquivos.sort()
    return lista_de_arquivos


def gerar_hashes_atuais(diretorio_raiz):
    """
    Retorna um dicionário {caminho_relativo: hash_sha256} para todos os
    arquivos presentes atualmente no diretório informado.

    Essa função representa o "estado atual" do diretório, seja para
    salvar pela primeira vez, seja para comparar com um estado antigo.
    """
    hashes_atuais = {}
    for caminho_relativo in listar_arquivos_recursivo(diretorio_raiz):
        caminho_completo = os.path.join(diretorio_raiz, caminho_relativo)
        hash_calculado = calcular_sha256_arquivo(caminho_completo)
        # Só adiciona ao dicionário se o hash foi calculado com sucesso
        # (isto é, se o arquivo pôde ser lido normalmente).
        if hash_calculado is not None:
            hashes_atuais[caminho_relativo] = hash_calculado
    return hashes_atuais


def salvar_hashes(hashes_dict, caminho_saida=NOME_ARQUIVO_HASHES):
    """
    Salva o dicionário de hashes no formato exato:
        caminho_do_arquivo:hash
    (uma linha por arquivo).
    """
    with open(caminho_saida, "w", encoding="utf-8") as f:
        # sorted() garante que a gravação sempre siga a mesma ordem
        # alfabética, independentemente da ordem em que o dicionário
        # foi montado internamente.
        for caminho_relativo in sorted(hashes_dict.keys()):
            f.write(f"{caminho_relativo}:{hashes_dict[caminho_relativo]}\n")


def carregar_hashes_registrados(caminho_arquivo=NOME_ARQUIVO_HASHES):
    """
    Lê o arquivo hashes.txt (formato caminho_do_arquivo:hash) e retorna
    um dicionário {caminho_relativo: hash_sha256}.

    Faz o parsing manualmente, dividindo pelo ÚLTIMO ':' da linha, já que
    o caminho do arquivo pode conter ':' (raro, mas evitamos quebrar nesse caso).

    Esse dicionário representa o "estado antigo" (registrado anteriormente),
    que será comparado com o estado atual do diretório.
    """
    hashes_registrados = {}
    if not os.path.isfile(caminho_arquivo):
        # Se o arquivo de registro nem existe, não há como comparar —
        # avisamos o usuário e encerramos o programa.
        print(f"[ERRO] Arquivo '{caminho_arquivo}' não encontrado. "
              f"Execute primeiro sem a flag --verificar para gerar o registro inicial.")
        sys.exit(1)

    with open(caminho_arquivo, "r", encoding="utf-8") as f:
        for numero_linha, linha in enumerate(f, start=1):
            linha = linha.rstrip("\n")  # remove só a quebra de linha do final
            if not linha.strip():
                continue  # pula linhas em branco
            if ":" not in linha:
                print(f"[AVISO] Linha {numero_linha} de '{caminho_arquivo}' fora do formato esperado, ignorando.")
                continue
            # rsplit(":", 1) divide a string a partir da DIREITA, no
            # máximo em 1 ponto de divisão. Ou seja, para
            # "pasta:sub:arquivo.txt:abc123", isso separa em
            # ["pasta:sub:arquivo.txt", "abc123"] — preservando ":" que,
            # por acaso, façam parte do próprio nome do arquivo.
            caminho_relativo, hash_registrado = linha.rsplit(":", 1)
            hashes_registrados[caminho_relativo] = hash_registrado

    return hashes_registrados


def comparar_estados(hashes_registrados, hashes_atuais):
    """
    Compara manualmente o dicionário de hashes registrados com o dicionário
    de hashes atuais e classifica cada arquivo em uma das quatro categorias:
        - novos
        - removidos
        - modificados
        - inalterados
    """
    novos = []
    removidos = []
    modificados = []
    inalterados = []

    # set(...) transforma as chaves do dicionário (os caminhos dos arquivos)
    # em um "conjunto", uma estrutura que permite operações rápidas de
    # comparação, como diferença (-) e intersecção (&).
    caminhos_registrados = set(hashes_registrados.keys())
    caminhos_atuais = set(hashes_atuais.keys())

    # "atuais - registrados" = caminhos que existem no atual, mas NÃO
    # existiam no registro antigo -> são arquivos NOVOS.
    for caminho in caminhos_atuais - caminhos_registrados:
        novos.append(caminho)

    # "registrados - atuais" = caminhos que existiam no registro antigo,
    # mas NÃO existem mais agora -> são arquivos REMOVIDOS.
    for caminho in caminhos_registrados - caminhos_atuais:
        removidos.append(caminho)

    # "atuais & registrados" (intersecção) = caminhos que existem nos
    # DOIS conjuntos -> para esses, precisamos olhar se o hash mudou ou não.
    for caminho in caminhos_atuais & caminhos_registrados:
        if hashes_atuais[caminho] != hashes_registrados[caminho]:
            modificados.append(caminho)  # mesmo nome, conteúdo diferente
        else:
            inalterados.append(caminho)  # mesmo nome, mesmo conteúdo

    # Ordena cada lista só para a exibição ficar organizada.
    novos.sort()
    removidos.sort()
    modificados.sort()
    inalterados.sort()

    return novos, removidos, modificados, inalterados


def imprimir_relatorio(novos, removidos, modificados, inalterados):
    """Apenas formata e imprime na tela as quatro listas de resultado."""
    print("=" * 60)
    print("RELATÓRIO DE VERIFICAÇÃO DE INTEGRIDADE")
    print("=" * 60)

    print(f"\n[+] Arquivos novos ({len(novos)}):")
    for caminho in novos:
        print(f"    + {caminho}")

    print(f"\n[-] Arquivos removidos ({len(removidos)}):")
    for caminho in removidos:
        print(f"    - {caminho}")

    print(f"\n[!] Arquivos modificados ({len(modificados)}):")
    for caminho in modificados:
        print(f"    ! {caminho}")

    print(f"\n[=] Arquivos inalterados ({len(inalterados)}):")
    for caminho in inalterados:
        print(f"    = {caminho}")

    print("\n" + "=" * 60)
    total = len(novos) + len(removidos) + len(modificados) + len(inalterados)
    print(f"Total de arquivos analisados: {total}")
    print("=" * 60)


def main():
    """
    Ponto de entrada: lê os argumentos da linha de comando e decide se
    deve GERAR o registro de hashes ou VERIFICAR contra o registro existente.
    """
    if len(sys.argv) < 2:
        print("Uso:")
        print(f"  python {sys.argv[0]} <diretorio>              -> gera {NOME_ARQUIVO_HASHES}")
        print(f"  python {sys.argv[0]} <diretorio> --verificar  -> compara com {NOME_ARQUIVO_HASHES}")
        sys.exit(1)

    diretorio = sys.argv[1]
    # Verifica se a flag "--verificar" está presente em algum dos
    # argumentos extras (a partir da posição 2).
    modo_verificar = "--verificar" in sys.argv[2:]

    if not os.path.isdir(diretorio):
        print(f"[ERRO] O caminho '{diretorio}' não é um diretório válido.")
        sys.exit(1)

    print(f"Calculando hashes SHA-256 de todos os arquivos em '{diretorio}' (recursivo)...")
    # Independente do modo, sempre calculamos o estado ATUAL do diretório
    # primeiro — é isso que será salvo (modo normal) ou comparado (modo --verificar).
    hashes_atuais = gerar_hashes_atuais(diretorio)
    print(f"{len(hashes_atuais)} arquivo(s) processado(s).")

    if not modo_verificar:
        # Modo normal (primeira execução): apenas grava o estado atual
        # como referência para o futuro.
        salvar_hashes(hashes_atuais)
        print(f"Registro salvo em '{NOME_ARQUIVO_HASHES}'.")
    else:
        # Modo --verificar: carrega o estado antigo, compara com o atual
        # e mostra o relatório de diferenças.
        hashes_registrados = carregar_hashes_registrados()
        novos, removidos, modificados, inalterados = comparar_estados(hashes_registrados, hashes_atuais)
        imprimir_relatorio(novos, removidos, modificados, inalterados)


if __name__ == "__main__":
    main()
