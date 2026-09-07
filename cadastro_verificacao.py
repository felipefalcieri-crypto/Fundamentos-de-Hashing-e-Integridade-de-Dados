"""
cadastro_verificacao.py

Simula um módulo simples de cadastro e autenticação de usuários usando
SHA-256 com salt aleatório por usuário.

Uso:
    python cadastro_verificacao.py --cadastrar usuario senha
    python cadastro_verificacao.py --verificar usuario senha

Formato do arquivo usuarios.txt:
    usuario:salt_hex:hash_hex

Regras de segurança seguidas:
    - A senha em texto claro NUNCA é armazenada; apenas o salt e o hash
      resultante de SHA-256(salt + senha) são gravados.
    - O salt é gerado com os.urandom (16 bytes = 128 bits, criptograficamente seguro).
    - Strings são convertidas para bytes usando UTF-8; bytes (salt e hash)
      são armazenados/lidos em texto usando representação hexadecimal.
"""

import sys
import os
import hashlib

NOME_ARQUIVO_USUARIOS = "usuarios.txt"
TAMANHO_SALT_BYTES = 16


def gerar_salt():
    """
    Gera um salt aleatório criptograficamente seguro de 16 bytes.

    os.urandom() usa o gerador de números aleatórios do próprio sistema
    operacional (que puxa "entropia" de fontes físicas, como ruído de
    hardware), o que é bem diferente de usar random.random() do Python,
    que NÃO é seguro para fins criptográficos (é previsível).
    """
    return os.urandom(TAMANHO_SALT_BYTES)


def calcular_hash_com_salt(salt_bytes, senha_str):
    """
    Concatena salt + senha (em bytes) e calcula o SHA-256.
    hashlib é usado aqui apenas para o cálculo unitário do hash.
    """
    # A senha chega como texto (str), mas o hash trabalha com bytes,
    # então precisamos converter com .encode("utf-8") primeiro.
    senha_bytes = senha_str.encode("utf-8")

    hasher = hashlib.sha256()
    # "salt_bytes + senha_bytes" simplesmente gruda os dois blocos de
    # bytes um atrás do outro antes de calcular o hash. É essa
    # concatenação que faz a mesma senha gerar hashes diferentes quando
    # o salt é diferente.
    hasher.update(salt_bytes + senha_bytes)
    return hasher.hexdigest()


def carregar_usuarios(caminho_arquivo=NOME_ARQUIVO_USUARIOS):
    """
    Lê o arquivo usuarios.txt e retorna um dicionário:
        {usuario: (salt_hex, hash_hex)}
    """
    usuarios = {}
    if not os.path.isfile(caminho_arquivo):
        # Se o arquivo ainda não existe (nenhum cadastro foi feito),
        # devolvemos um dicionário vazio em vez de dar erro.
        return usuarios

    with open(caminho_arquivo, "r", encoding="utf-8") as f:
        for numero_linha, linha in enumerate(f, start=1):
            linha = linha.rstrip("\n")
            if not linha.strip():
                continue
            # Cada linha tem exatamente 3 campos separados por ":"
            # (usuario, salt em hexadecimal, hash em hexadecimal).
            partes = linha.split(":")
            if len(partes) != 3:
                print(f"[AVISO] Linha {numero_linha} de '{caminho_arquivo}' fora do formato esperado, ignorando.")
                continue
            usuario, salt_hex, hash_hex = partes
            usuarios[usuario] = (salt_hex, hash_hex)
    return usuarios


def salvar_novo_usuario(usuario, salt_hex, hash_hex, caminho_arquivo=NOME_ARQUIVO_USUARIOS):
    """
    Acrescenta um novo registro ao final do arquivo usuarios.txt.

    O modo "a" (append) escreve no FINAL do arquivo, sem apagar os
    registros que já existiam — diferente do modo "w" (write), que
    substituiria todo o conteúdo anterior.
    """
    with open(caminho_arquivo, "a", encoding="utf-8") as f:
        f.write(f"{usuario}:{salt_hex}:{hash_hex}\n")


def cadastrar(usuario, senha):
    """
    Fluxo de cadastro de um novo usuário.
    """
    usuarios_existentes = carregar_usuarios()
    if usuario in usuarios_existentes:
        print(f"[ERRO] Usuário '{usuario}' já está cadastrado.")
        sys.exit(1)

    # 1) Gera um salt novo e aleatório para ESTE usuário especificamente
    #    (cada cadastro tem seu próprio salt, mesmo que duas pessoas
    #    escolham a mesma senha).
    salt_bytes = gerar_salt()

    # 2) Calcula o hash de salt + senha.
    hash_hex = calcular_hash_com_salt(salt_bytes, senha)

    # 3) Converte o salt (que está em bytes) para uma representação em
    #    texto hexadecimal, já que arquivos de texto não guardam bytes
    #    "crus" de forma prática — o hexadecimal é a forma padrão de
    #    representar bytes como texto legível (ex: b'\x1f\xa3' vira "1fa3").
    salt_hex = salt_bytes.hex()

    # 4) Salva usuario:salt:hash no arquivo. Note que a variável "senha"
    #    (texto original) NUNCA é escrita em lugar nenhum — só o hash dela.
    salvar_novo_usuario(usuario, salt_hex, hash_hex)
    print(f"Usuário '{usuario}' cadastrado com sucesso.")


def verificar(usuario, senha):
    """
    Fluxo de verificação (login) de um usuário já cadastrado.
    """
    usuarios_existentes = carregar_usuarios()

    if usuario not in usuarios_existentes:
        # Por segurança, não dizemos "usuário não existe" de forma
        # diferente de "senha errada" — sempre respondemos "Acesso negado",
        # para não dar pistas a quem está tentando adivinhar usuários válidos.
        print("Acesso negado")
        sys.exit(1)

    salt_hex, hash_hex_armazenado = usuarios_existentes[usuario]

    # bytes.fromhex() faz o caminho inverso de .hex(): pega o texto
    # hexadecimal salvo no arquivo e reconstrói os bytes originais do salt.
    salt_bytes = bytes.fromhex(salt_hex)

    # Recalcula o hash usando o MESMO salt que foi usado no cadastro,
    # combinado com a senha que a pessoa está digitando agora.
    hash_hex_calculado = calcular_hash_com_salt(salt_bytes, senha)

    # Compara o hash recém-calculado com o hash que estava guardado.
    # Se a senha digitada agora for igual à do cadastro, os dois hashes
    # vão bater exatamente.
    acesso_concedido = comparar_hashes_em_tempo_constante(hash_hex_calculado, hash_hex_armazenado)

    if acesso_concedido:
        print("Acesso permitido")
    else:
        print("Acesso negado")


def comparar_hashes_em_tempo_constante(hash_a, hash_b):
    """
    Compara duas strings de hash (hex) manualmente, caractere a caractere,
    sempre percorrendo todo o comprimento do maior hash. Isso evita que a
    comparação termine mais cedo apenas porque os primeiros caracteres já
    diferem (mitigação básica contra ataques de timing).

    Por que não usar simplesmente "hash_a == hash_b"? Porque o Python (e
    a maioria das linguagens) compara string por string PARANDO assim que
    encontra a primeira diferença. Isso significa que comparar
    "aXXXXX" com "abYYYY" é um pouquinho mais rápido do que comparar
    "abXXXX" com "abYYYY" (porque a primeira diferença aparece mais cedo).
    Um atacante muito sofisticado, medindo esse tempo com precisão, poderia
    tentar descobrir o hash certo caractere por caractere. Percorrendo
    sempre TODOS os caracteres, não importa se já achamos uma diferença,
    fechamos essa brecha.
    """
    tamanho_maximo = max(len(hash_a), len(hash_b))
    # Se os tamanhos já forem diferentes, já sabemos que não são iguais,
    # mas mesmo assim continuamos o loop inteiro (não damos "return" cedo).
    diferenca_encontrada = len(hash_a) != len(hash_b)

    for i in range(tamanho_maximo):
        # Pega o caractere na posição i de cada hash, ou None se a
        # posição não existir (string mais curta).
        caractere_a = hash_a[i] if i < len(hash_a) else None
        caractere_b = hash_b[i] if i < len(hash_b) else None
        if caractere_a != caractere_b:
            diferenca_encontrada = True
        # Repare que NÃO damos "break" aqui, mesmo já sabendo que os
        # hashes são diferentes — o loop continua até o fim de propósito.

    return not diferenca_encontrada


def main():
    """
    Ponto de entrada: lê o modo (--cadastrar ou --verificar), o nome de
    usuário e a senha a partir da linha de comando.
    """
    if len(sys.argv) != 4 or sys.argv[1] not in ("--cadastrar", "--verificar"):
        print("Uso:")
        print(f"  python {sys.argv[0]} --cadastrar usuario senha")
        print(f"  python {sys.argv[0]} --verificar usuario senha")
        sys.exit(1)

    modo = sys.argv[1]
    usuario = sys.argv[2]
    senha = sys.argv[3]

    if modo == "--cadastrar":
        cadastrar(usuario, senha)
    else:
        verificar(usuario, senha)


if __name__ == "__main__":
    main()
