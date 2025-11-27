# Cloud Security Telemetry – AWS + Prometheus + Grafana

Laboratório de observabilidade focado em **segurança em nuvem**.  
A ideia é trazer sinais do AWS (CloudTrail, GuardDuty, IAM e KMS) para dentro da mesma lógica de métricas, SLOs e dashboards que eu usei nos labs anteriores de SRE + AppSec.

Este repositório é o **Lab 3** da série de laboratórios:

- Dia 1: transformar risco de login em métricas
- Dia 2: transformar métricas em alertas + evidência automática
- Dia 3 (este): transformar sinais de segurança da nuvem em **SLIs/SLOs de controle**

---

## Visão Geral

O objetivo do lab é expor, via Prometheus, um conjunto mínimo de sinais de postura de segurança em nuvem:

- Se o **CloudTrail** está com logging habilitado
- Se existem **findings de alta severidade no GuardDuty**
- Qual a **idade máxima de chaves de acesso IAM** (para rotação)
- Se as **chaves KMS gerenciadas pelo cliente** têm **rotação automática** habilitada

Tudo isso é exposto por um **exporter em Python**, coletado pelo **Prometheus** e visualizado em um dashboard **Grafana** chamado:

> `Cloud Security Posture Overview`

A partir daí, fica muito mais fácil traduzir requisitos de GRC/ITGC em **coisas que quebram ou ficam vermelhas** quando a postura degrada.

---

## Arquitetura do laboratório

Fluxo de ponta a ponta:

1. **AWS**  
   - CloudTrail, GuardDuty, IAM e KMS expõem APIs via AWS SDK (boto3).

2. **Exporter Python (`aws_exporter.py`)**
   - Usa um usuário IAM de leitura para consultar o estado de cada serviço.
   - Converte o resultado em métricas Prometheus.

3. **Prometheus**
   - Faz scrape do exporter a cada poucos segundos.
   - Exponibiliza as métricas para consulta via PromQL.

4. **Grafana**
   - Usa o Prometheus como data source.
   - Mostra um painel de postura de segurança com SLOs de nuvem.

Em termos de componentes:

```text
AWS (CloudTrail/GuardDuty/IAM/KMS)
        ↓ boto3
Python Exporter (aws_exporter.py)
        ↓ /metrics
    Prometheus
        ↓
      Grafana
```

---

## Métricas de Nuvem

O exporter expõe quatro métricas principais (além das métricas padrão do runtime Python).

### 1. `aws_cloudtrail_logging_enabled`

- **Tipo:** Gauge (`0` ou `1`)
- **Significado:**  
  `1` → Pelo menos um trail com logging habilitado  
  `0` → Nenhum trail em logging
- **SLO:** CloudTrail deve permanecer habilitado 100% do tempo.
- **ITGC:** Logging & Monitoring (trilha de auditoria de ações na conta).

### 2. `aws_guardduty_high_findings`

- **Tipo:** Gauge (inteiro)
- **Significado:**  
  Número de findings de severidade >= 7 no GuardDuty.
- **Valores especiais:**
  - `0` → Nenhum finding de alta severidade
  - `> 0` → Há findings de alta severidade em aberto
  - `-1` → GuardDuty não está habilitado / sem subscription
- **SLO:** Nenhum finding de alta severidade em aberto.
- **ITGC:** Monitoramento de segurança / detecção de ameaças.

### 3. `aws_iam_access_key_max_age_days`

- **Tipo:** Gauge
- **Significado:**  
  Idade máxima (em dias) entre todas as chaves de acesso **ativas** de todos os usuários IAM.
- **SLO sugerido:** `< 90` dias.
- **ITGC:** Acesso lógico / gestão de credenciais (rotação de chaves).

### 4. `aws_kms_rotation_all_enabled`

- **Tipo:** Gauge (`0` ou `1`)
- **Significado:**  
  - `1` → Todas as chaves **KMS gerenciadas pelo cliente (CUSTOMER)** têm rotação automática habilitada.  
  - `0` → Pelo menos uma CMK sem rotação automática ou erro na coleta.
- **SLO:** 100% das CMKs com rotação automática.
- **ITGC:** Gestão de chaves criptográficas.

> Observação: o exporter ignora chaves gerenciadas pela AWS (`KeyManager = "AWS"`), pois o foco do controle está em chaves que o time de segurança realmente administra.

---

## Pré-requisitos

- Conta AWS com:
  - CloudTrail configurado (idealmente multi-região)
  - (Opcional) GuardDuty habilitado
  - Usuário(s) IAM com chaves de acesso
  - (Opcional) CMKs gerenciadas pelo cliente no KMS
- AWS CLI configurado localmente
- Docker e Docker Compose
- Python 3.10+ (caso queira rodar o exporter direto, sem Docker)

---

## Usuário IAM de Monitoramento

Criei um usuário IAM dedicado, com permissão apenas de leitura para os sinais que o lab precisa.

Exemplo de política (resumida):

- CloudTrail
  - `cloudtrail:DescribeTrails`
  - `cloudtrail:GetTrailStatus`
- GuardDuty
  - `guardduty:ListDetectors`
  - `guardduty:ListFindings`
- IAM
  - `iam:ListUsers`
  - `iam:ListAccessKeys`
  - `iam:GetAccessKeyLastUsed` (opcional, se quiser enriquecer)
- KMS
  - `kms:ListKeys`
  - `kms:DescribeKey`
  - `kms:GetKeyRotationStatus`

Depois disso, configurei um profile dedicado:

```bash
aws configure --profile cloud-telemetry-monitor
```

O exporter usa esse profile via boto3:

```python
session = boto3.Session(profile_name="cloud-telemetry-monitor")
```

---

## Estrutura do Repositório

```text
project-3-cloud-security-telemetry/
  ├── exporters/
  │     └── aws_exporter.py 
  ├── docker-compose.yml  
  ├── prometheus.yml 
  ├── requirements.txt  
  └── README.md  
```

---

## Rodando com Docker Compose

1. Certifique-se de que o profile `cloud-telemetry-monitor` está configurado em `~/.aws`.
2. No diretório do projeto, execute:

```bash
docker compose up -d --build
```

Isso irá subir:

- `aws-exporter` – container com o exporter Python
- `prometheus` – coletando métricas do exporter
- `grafana` – para visualizar o dashboard

3. Acesse os serviços:

- Prometheus: <http://localhost:9090>
- Grafana: <http://localhost:3000>

Usuário/senha padrão do Grafana (conforme `docker-compose.yml`):

- usuário: `admin`
- senha: `admin` (pede alteração no primeiro login)

---

## Configurando o Prometheus

O arquivo `prometheus.yml` contém um job simples para o exporter:

```yaml
global:
  scrape_interval: 5s

scrape_configs:
  - job_name: 'aws-cloud-security-exporter'
    static_configs:
      - targets: ['aws-exporter:9100']
```

Dentro da rede do Docker Compose, o Prometheus enxerga o exporter pelo nome de serviço `aws-exporter`.

Você pode validar que o target está **UP** na UI do Prometheus em:

- `Status` → `Targets`

---

## Dashboard no Grafana – Cloud Security Posture Overview

Com o data source Prometheus apontando para `http://prometheus:9090`, criei um dashboard chamado:

> **Cloud Security Posture Overview**

Painéis principais:

1. **CloudTrail Logging Status**  
   - Query: `aws_cloudtrail_logging_enabled`  
   - Visualização: Stat ou Gauge (0/1)  
   - SLO: sempre 1.

2. **GuardDuty: High Severity Findings**  
   - Query: `aws_guardduty_high_findings`  
   - Mapeamento:  
     - `0` → OK  
     - `>0` → alerta vermelho  
     - `-1` → GuardDuty não habilitado.

3. **IAM Access Key Rotation Compliance**  
   - Query: `aws_iam_access_key_max_age_days`  
   - Linha de referência em 90 dias  
   - Quando passa de 90, estou violando a política de rotação.

4. **KMS Key Rotation Status**  
   - Query: `aws_kms_rotation_all_enabled`  
   - 1 = todas as CMKs com rotação automática  
   - 0 = pelo menos uma CMK sem rotação.

A ideia não é ser um “painel definitivo de segurança em nuvem”, mas um **MVP de postura** que cabe em uma única tela e conversa bem com times de GRC e auditoria.

---

## Mapeamento ITGC / GRC → Métricas

Uma forma de enxergar este lab é como um mapa entre linguagem de controle e linguagem de SRE:

| Domínio GRC / ITGC                    | Controle                                                        | Métrica Prometheus                         |
|--------------------------------------|------------------------------------------------------------------|--------------------------------------------|
| Logging & Monitoring                 | Trilha de auditoria de ações do usuário                         | `aws_cloudtrail_logging_enabled`           |
| Monitoramento de segurança           | Detecção de atividades suspeitas / ameaças                      | `aws_guardduty_high_findings`              |
| Acesso lógico / credenciais          | Rotação periódica de chaves de acesso                           | `aws_iam_access_key_max_age_days`          |
| Gestão de chaves criptográficas      | Rotação automática de chaves de criptografia gerenciadas pelo cliente | `aws_kms_rotation_all_enabled`      |

Com isso, “tenho controle” deixa de ser uma frase vaga e passa a ser algo que eu consigo ver **vermelho ou verde** em menos de 10 segundos.


