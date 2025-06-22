# Operações de Segurança e Gestão de Incidentes - Projeto
##  Introdução
No âmbito da unidade curricular “Operações de Segurança e Gestão de Incidente” foi proposto ao grupo a realização de um projeto focado nos temas lecionados ao longo do semestre. Desta forma, tendo em conta as novas tecnologias, em especial da Inteligência Artificial, o grupo optou por atender às necessidades das empresas quanto a ataques cibernéticos, através da utilização da Inteligência Artificial para a deteção e proteção contra estes mesmos ataques. No entanto, devido à alta variedade de ataques, o grupo decidiu apenas focar-se na deteção e proteção contra ataques de negação de serviço. O seguinte projeto inclui o lançamento de 1 container servidor, 4 containers benignos, 1 container maligno todos utilizando a ferramenta Docker. Além disso no container Servidor, encontra-se um dashboard que faz a monitorização da rede e respetivos IPs.

## 1. Utilização do Projeto

## 1.1 Construir os containers
- docker compose build

## 1.2 Lançar containers
- **NOTA:** ATENÇÂO AO LANÇAR O CONTAINER MALIGNO. ELE ENVIA 20000 PACOTES POR SEGUNDO OU MAIS. RESULTA EM 20000 LOGS POR SEGUNDO

### 1.2.1 BENIGNOS:
- docker compose up -d servidor benigno_1 benigno_2 benigno_3 benigno_4

### 1.2.2 MALIGNO
- docker compose up -d maligno_burst
- Parar o maligno: docker compose stop maligno_burst

# 2. Aplicação Web

- Após os containers serem lançados, em específico, o servidor, a aplicação web irá abrir no endereço http://localhost:5000. Ao aceder à aplicação web é possível observar o dashboard onde é feita a monitorização dos pacotes de rede.

# 3. Notas

- A pasta logs_demo tem como propósito o treino do algoritmo no ficheiro de jupyter notebook. Ao correr o algoritmo os logs vão ser guardados na pasta logs (porderá ser necessário apagar esta pasta caso esteja a ocupar bastante espaço.
