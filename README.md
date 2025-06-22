# 1. Comandos para iniciar o docker

## 1.1 Construir
- docker compose build

## 1.2 Lançar containers
- **NOTA:** ATENÇÂO AO LANÇAR O CONTAINER MALIGNO. ELE ENVIA 20000 PACOTES POR SEGUNDO OU MAIS. RESULTA EM 20000 LOGS POR SEGUNDO

### 1.2.1 BENIGNOS:
- docker compose up -d servidor benigno_1 benigno_2 benigno_3 benigno_4

### 1.2.2 MALIGNO
- docker compose up -d maligno_burst
- Parar o maligno: docker compose stop maligno_burst

# 2. Script para correr o algoritmo

- Nome: alg_dosDetect.py
- É uma função que retorna a lista com os IPs considerados "anomalia".

# 3. Notas

- A pasta logs_demo serve para o notebook, não mexer nessa pasta. Ao correrem o algoritmo os logs vão ser guardados na pasta logs.
- Cada vez que correrem o container maligno, e assim o necessitarem apaguem a pasta "logs" porque vai ficar a ocupar muito espaço se não o fizerem. SUGESTÃO: Mecanismo para
 apagar os logs que já existam à mais de x tempo de forma a apagar logs à medida que entram novos!.
- Mais uma vez, não lançar os containers todos ao mesmo tempo. Lançar primeiro os benignos, e quando quiserem atacar, lançem o maligno. Assim que lançarem o maligno corram o comando para o parar, ou caso a firewall ja esteja implementada em príncipio bloqueia o ip maligno.
