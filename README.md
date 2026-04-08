# Teste-AES128
Este projeto busca verificar o Efeito Avalanche no AES-128 e no modo Cypher Block Chaining (CBC) 
Foi usado especificamente a implementação AES disponível em: https://github.com/boppreh/aes

A idéia geral é capturar as saídas encriptidas (vamos chamar de parcialmente-encriptadas), com duas entradas quase idênticas,
após cada um dos 10 rounds de processamento e compará-las com o texto simples original e entre si, checando as diferenças nos bits e 
averiguando que, após os 10 rounds, os encriptados (partindo de chaves com apenas 1 bit de diferença)
mudam em média 50% dos seus bits e são, essencialmente, ilegíveis
