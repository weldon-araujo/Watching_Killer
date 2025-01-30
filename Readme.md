<h1 align="center" >Watching Killer</h1>

<h4 align="center">

 ![Imgur](https://i.imgur.com/AAoJIuV.jpg)

</h4>

<h1>Descrição do projeto</h1>

Essa é uma toolkit que para realizar automação do processo de cyber threat hunting, ela possui funcionalidades como extração de IOCs e artefatos de fontes não estruturadas, consulta de reputações de endereços IP ou relatório de análise de exploits públicos esse aparato auxilia no processo de embasado pela metodologia TAHITI (Targeted Hunting integrating Threat Intelligence)

<h3></h3>


<h4 align="center">
  
   :construction: Projeto em desenvolvimento:construction:

</h4>

<h3></h3>

<!-- Modo de uso-->

<h1>Modo de uso</h1>

* Após realizar clonagem do repositório é necessário instalar as libs externas simplesmente executando **pip install -r requirements.txt** estando no diretório raiz do reposítório ou repassando o caminho absoluto até o arquivo **requirements.txt**.
* <p>Para visualizar ajuda e verificar os parâmetros necessários, ou se caso execute o script principal Watching_Killer.py sem parâmetros.</p>

```
python.exe .\Watching_Killer.py -h

ou 

python.exe .\Watching_Killer.py --help

```
<h4 align="center">

![img](https://i.imgur.com/29zIWlb.png)

</h4>

* A ferramenta necessita do repasse de algum arquivo que contenha os valores que deseje extratir, podendo até mesmo está desestruturado, podendo ser arquivos TXT ou CSV, como no exemplo abaixo uma fonte com vários IOCs de forma desestruturada em um aquivo TXT.

<h4 align="center">

![img](https://i.imgur.com/TMFtz5i.png)

</h4>

* A usabilidade é a mesma para demais argumentos --md5, --sha1, --sha256, --domain, --cve, --email, --reg e --artifact 

<h4 align="center">

![img](https://i.imgur.com/uBMUlM3.png)

</h4>

* O argumento de reputação "--reputation" utiliza o serviço de API do https://docs.abuseipdb.com/#introduction portanto pra uso desse argumento é necessário possuir uma chave de API desse serviço, que disponibiliza até 1K checks diários na categoria free, a ferramenta usa preferencialmente o arquivo .env com o valor key atribuido a váriavel **abuseipdbkey**, então na mesma raiz onde foi clonado o projeto basta criar o arquivo .env com exatamente o mesmo nome de variável como na figura a seguir e inserir a chave.

<h4 align="center">

![img](https://i.imgur.com/Z5q8k6y.png)

</h4>

* Essa funcionalidade deve obrigatoriamente ser utilizada junto ao argumento "--ip" pois ela irá consultar a reputação dos IPs extraidos do arquivo de origem.
* Após essa inserção a ferramenta estará apta a realização de consulta de reputação dos endereços IPs extraidos da fonte de IOCs.

<h4 align="center">

![img](https://i.imgur.com/3xwtlsg.png)

</h4>

<h4>
 
* É como que em relatórios e artigos de inteligência que geralmente são os trigers utilizados para iniciar investigações, artefatos principalmente não venho no padrão de nomenclatura normal, por exemplo, o relatório pode abordar algum TTP que utilize cmd, ao invés de mencionar cmd.exe que é o padrão que a ferramenta consegue extrair, o agumento "-i" ou "--include" serve para serem repassados valores que usuário deseje inserir nas queries de resposta.

* No exemplo abaixo é possível notar a presença dos processos cmd.exe e powershell.exe no arquivo de origem.

![img](https://i.imgur.com/qTnO4iH.png)

* Na execução da ferramenta está sendo inserido os valores mimikatz.exe e vssadmin.exe via argumento "-i" 

![img](https://i.imgur.com/s7wuXIn.png)

* A ferramenta conta com um módulo de relatório que retorna uma análise de exploits disponpiveis em bases públicas como exploitDB e Packet storm e sugere queries expecíficas com base nos pontos chave identificados nos exploits, a base que guarda as análise fica contida neste repositório que atualmente está bem pequena mas que tende a evoluir, o argumento deve obrigatoriamente ser utilizado junto a opção "--cve", pois ela irá se basear nos valores extraidos do arquivo de origem para verificar se já há análise de exploits das CVEs extraidaa.

* Usabilidade

![img](https://i.imgur.com/bFGbF5w.png)

* Relatório será gerado no mesmo diretório do projeto clonado.

![img](https://i.imgur.com/4kD0BJI.png)

![img](https://i.imgur.com/0sOMNz5.png)

</h4>



