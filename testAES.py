import statistics
from aes import AES, bytes2matrix, matrix2bytes, sub_bytes, shift_rows, mix_columns, add_round_key, xor_bytes

NUSP = "15495668"
j = int(NUSP[-1])

def get_nuspb128_as_bytes(nusp_str):
    binary_str = "".join(bin(int(d))[2:].zfill(4) for d in nusp_str) # [2:] aqui pois o binario começa com "0b"
    nuspb = binary_str.lstrip('0')
    nuspb128_str = (nuspb * (128 // len(nuspb) + 1))[:128]
    
    val = int(nuspb128_str, 2)
    return val.to_bytes(16, byteorder='big')

def get_bits_bin(buffer):
    if isinstance(buffer, bytes):
        return bin(int.from_bytes(buffer, byteorder='big'))[2:].zfill(128)
    return bin(buffer)[2:].zfill(128)

def bits_diff(bin1, bin2):
    posicoes = [i for i in range(128) if bin1[i] != bin2[i]]
    return len(posicoes), posicoes

class AESAvalanche(AES):
    def encrypt_with_rounds(self, plaintext_bytes):
        states = []
        state = bytes2matrix(plaintext_bytes)
        add_round_key(state, self._key_matrices[0])
        states.append(get_bits_bin(matrix2bytes(state)))

        for i in range(1, self.n_rounds):
            sub_bytes(state)
            shift_rows(state)
            mix_columns(state)
            add_round_key(state, self._key_matrices[i])
            states.append(get_bits_bin(matrix2bytes(state)))

        sub_bytes(state)
        shift_rows(state)
        add_round_key(state, self._key_matrices[-1])
        states.append(get_bits_bin(matrix2bytes(state)))
        return states

def parte_1():
    key_bytes = get_nuspb128_as_bytes(NUSP)
    nuspb128_hex = key_bytes.hex().upper()
    print(f"O meu NUSP na base 10 é {NUSP}, e o NUSPb128 (em HEX) é {nuspb128_hex} j={j}")

    e1_bin = get_bits_bin(key_bytes)
    lista_bits = list(e1_bin)
    lista_bits[j] = '1' if lista_bits[j] == '0' else '0'
    e2_bin = "".join(lista_bits)
    
    e1_bytes = int(e1_bin, 2).to_bytes(16, 'big')
    e2_bytes = int(e2_bin, 2).to_bytes(16, 'big')

    cipher = AESAvalanche(key_bytes)
    rounds_e1 = cipher.encrypt_with_rounds(e1_bytes)
    rounds_e2 = cipher.encrypt_with_rounds(e2_bytes)

    diff_counts = []
    for i in range(len(rounds_e1)):
        count, pos = bits_diff(rounds_e1[i], rounds_e2[i])
        diff_counts.append(count)
        hex1 = hex(int(rounds_e1[i], 2))[2:].upper().zfill(32)
        hex2 = hex(int(rounds_e2[i], 2))[2:].upper().zfill(32)
        print(f"As duas entradas para o round {i} são (em HEX) {hex1} e {hex2}\n")
        print(f"E o número de bits diferentes nas mesmas posições da entrada é {count} nas posições {pos}\n")

    media = statistics.mean(diff_counts)
    desvio = statistics.stdev(diff_counts)
    print(f"Para todas as saídas dos rounds, o número médio de bits diferentes nas mesmas posições é {media:.2f} e o desvio padrão é {desvio:.2f}")

def parte_2():
    # obs: não entendi se era pra copiar esse texto, mas resolvi usar ele inteiro aqui
    texto = (
        "Para Juca de Oliveira, tudo começava e terminava em Shakespeare. "
        "\"A primeira grande influência que sofri de Shakespeare foi humildade e "
        "consciência de minhas limitações. Meus queridos e saudosos professores "
        "Paulo Mendonça e Alberto D'Aversa, da Escola de Arte Dramática, "
        "diziam: 'Se você tiver alguma dúvida sobre a natureza humana, consulte "
        "Shakespeare'. Quem escreve teatro não lê Shakespeare, consulta "
        "Shakespeare. Sempre. E é exatamente isso o que eu faço\", afirmou ele ao "
        "Estadão em 2014, quando estreou o monólogo Rei Lear, em que "
        "interpretava seis personagens. Ainda assim, a atuação não foi a primeira "
        "escolha de Oliveira. Nascido em São Roque, no interior de São Paulo, "
        "em 1935, seguiu a princípio um caminho distante das artes. "
        "Chegou a cursar Direito na Universidade de São Paulo, até que um teste "
        "vocacional mudou o rumo de sua vida ao indicar uma inclinação para o "
        "teatro. A descoberta foi decisiva. Ele abandonou a faculdade e passou a "
        "se dedicar integralmente à atuação, ingressando na Escola de Arte "
        "Dramática de São Paulo. Ali, encontrou não apenas uma profissão, mas "
        "uma vocação. O ator relembrou aquele momento em uma entrevista ao "
        "Caderno 2 em outubro de 1987. \"Eu tinha 15, 16 anos, e havia ido a "
        "Mairinque, perto de São Roque, onde havia um grupo amador, o Teatro "
        "dos Jovens. Um velho professor - Bertulini - dirigia algumas peças, "
        "Cala a Boca Etelvina, Saudade, do Paulo Magalhães, e me convidou para "
        "fazer uns papéis como coadjuvante nesses dois espetáculos. Fiz e gostei "
        "muito. Isso era por volta de 1953. Abandonei essa ideia durante muito "
        "tempo. Aí eu vi num jornal, aliás no Estado de S. Paulo, um anúncio: "
        "'Grupo jovem procura atores'. Aliás, o Grupo Talma, de amadores. Isso "
        "por volta de 1957. Fiquei entusiasmadíssimo. "
        "Procurei o pessoal e vim a saber que existia uma escola para formar atores.\""
    )

    key_bytes = get_nuspb128_as_bytes(NUSP)
    nuspb128_hex = key_bytes.hex().upper()
    
    print(f"O meu NUSP na base 10 é {NUSP}, e o NUSPb128 (em HEX) é {nuspb128_hex} j={j}")

    while len(texto) % 16 != 0:
        texto += " "

    # obs: estou usando latin-1 para ASCII estendido (não consegui fazer com .encode('ascii'))
    blocos_orig = [texto[i:i+16].encode('iso-8859-1') for i in range(0, len(texto), 16)]
    
    b1_bin_list = list(get_bits_bin(blocos_orig[0]))
    b1_bin_list[j] = '1' if b1_bin_list[j] == '0' else '0' # jeito meio idiota de inverter o bit j, mas fiz direto na string
    b1_alt_bytes = int("".join(b1_bin_list), 2).to_bytes(16, 'big')
    
    blocos_alt = [b1_alt_bytes] + blocos_orig[1:]

    cipher = AES(key_bytes)
    vi = key_bytes
    
    prev_orig = vi
    prev_alt = vi
    
    xor_diffs = []

    for i in range(len(blocos_orig)):
        in_orig = xor_bytes(blocos_orig[i], prev_orig)
        in_alt = xor_bytes(blocos_alt[i], prev_alt)
        
        count_in, pos_in = bits_diff(get_bits_bin(in_orig), get_bits_bin(in_alt))
        
        print(f"Os dois blocos de entrada para a {i+1}-ésima aplicação do AES são (em HEX): {in_orig.hex().upper()} e {in_alt.hex().upper()}")
        print(f"E o número de bits diferentes, nas mesmas posições da entrada, é {count_in} nas posições {pos_in}")

        out_orig = cipher.encrypt_block(in_orig)
        out_alt = cipher.encrypt_block(in_alt)
        
        count_out, pos_out = bits_diff(get_bits_bin(out_orig), get_bits_bin(out_alt))
        print(f"E os dois blocos na saída são (em HEX): {out_orig.hex().upper()} e {out_alt.hex().upper()}")
        print(f"E o número de bits diferentes, nas mesmas posições da saída, é {count_out} nas posições {pos_out}")
        
        count_xor, pos_xor = bits_diff(get_bits_bin(out_orig), get_bits_bin(out_alt))
        xor_diffs.append(count_xor)
        print(f"E o número de bits diferentes, nas mesmas posições, após o XOR no modo CBC é {count_xor} nas posições {pos_xor}")
        print("-" * 10)

        prev_orig = out_orig
        prev_alt = out_alt

    media_cbc = statistics.mean(xor_diffs)
    desvio_cbc = statistics.stdev(xor_diffs)
    print(f"Para todos os números de bits diferentes nas mesmas posições, após o XOR no modo CBC, o número médio é {media_cbc:.2f} e o desvio padrão é {desvio_cbc:.2f}")

    # Em teoria, a prob. de colisão de um bloco de 128 bits é 1/(2^128).
    print(f"A probabilidade de colisão no último bloco é {1/(2**128)}")
    print("O último bloco pode ser usado como identificador único do texto porque a probabilidade de dois textos diferentes resultarem no mesmo hash de 128 bits é desprezível.")

if __name__ == "__main__":
    print("parte 1:\n\n")
    parte_1()
    print("\n\nparte 2:\n\n")
    parte_2()
