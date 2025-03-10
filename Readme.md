<h1 align="center" >Watching Killer</h1>

<h4 align="center">

 ![Imgur](https://i.imgur.com/AAoJIuV.jpg)

</h4>

<h1>Descrição do projeto</h1>

O Watching Killer é uma toolkit cujo a função é realizar automação do processo de cyber threat hunting. Ela possui funcionalidades como: extração de IOCs e artefatos de fontes não estruturadas, consulta de reputações de endereços IPs e relatório de análise de exploits públicos. Esse aparato auxilía no processo que se baseia na metodologia <a href="https://www.betaalvereniging.nl/en/safety/tahiti/" target="_blank">TAHITI</a> (Targeted Hunting integrating Threat Intelligence)

<h3></h3>


<h4 align="center">
  
   :construction: Projeto em desenvolvimento:construction:

</h4>

<h3></h3>

<!-- Modo de uso-->

<h1>Modo de uso</h1>

* Após realizar a clonagem do repositório é necessário instalar as libs externas simplesmente executando **pip install -r requirements.txt** estando a partir do diretório raiz do repositório ou repassando o caminho absoluto até o arquivo **requirements.txt**.
* Para visualizar ajuda e verificar os parâmetros necessários execute o script principal Watching_Killer.py com argumento "-h" ou "--help".

```
python.exe .\Watching_Killer.py -h

ou 

python.exe .\Watching_Killer.py --help

```
<h4 align="center">

![img](https://i.imgur.com/29zIWlb.png)

</h4>

* A ferramenta necessita do repasse de um arquivo que contenha os valores a serem extraidos não importa se está ou não estruturado. A ferramenta tem suporte a arquivos do tipo TXT ou CSV assim como pode ser observado no exemplo abaixo.

<h4 align="center">

![img](https://i.imgur.com/TMFtz5i.png)

</h4>

* Como demonstrado no exemplo abaixo com o argumento "--ip", a usabilidade é a mesma para os demais argumentos --md5, --sha1, --sha256, --domain, --cve, --email, --reg e --artifact 

<h4 align="center">

![img](https://i.imgur.com/uBMUlM3.png)

</h4>
 
 * Muitas vezes é necessário se trabalhar com grandes quantidades de dados, alguns SIENs podem limitar a quantidade de consultas por queries, o argumento "-l" ou "--l" permite dividir os valores em 2 consultas como no exemplo abaixo.

<h4 align="center">
 
![img](https://i.imgur.com/sCeY7Gz.png)

</h4>

* O argumento de reputação "--reputation" utiliza o serviço de API do portal <a href="https://docs.abuseipdb.com/#introduction" target="_blank">AbuseipDB</a>, portanto pra uso desse argumento é necessário possuir uma chave de API desse serviço, que disponibiliza até 1K checks diários na categoria free, a ferramenta usa preferencialmente o arquivo .env com o valor key atribuido a váriavel **abuseipdbkey**, então na mesma raiz onde foi clonado o projeto basta criar um arquivo .env com exatamente o mesmo nome de variável como na figura a seguir e inserir a chave.

<h4 align="center">

![img](https://i.imgur.com/Z5q8k6y.png)

</h4>

* Essa funcionalidade deve obrigatoriamente ser utilizada junto ao argumento "--ip" ou "-ip" pois ela irá consultar a reputação dos IPs extraidos do arquivo de origem.
* Após essa inserção a ferramenta estará apta a realizar consultas de reputação dos endereços IPs extraidos do arquivo fonte de IOCs.

<h4 align="center">

![img](https://i.imgur.com/3xwtlsg.png)

</h4>
 
* Relatórios e artigos de inteligência geralmente são utilizados como trigers para iniciar investigações, contudo algumas vezes os valores a serem extraidos não estão no padrão de nomenclatura que a ferramenta consegue extrair, a títulos de exemplo, fontes de inteligência podem abordar alguns TTPs que utilize ferramentas como cmd, vssadmin entre outros. Eles podem não os descreverem na forma de processos, que seriam cmd.exe e vssadmin.exe que é o padrão que a ferramenta consegue extrair, o agumento "-i" ou "--include" serve para repassar valores que usuário deseje inserir nas queries de resposta.

* No exemplo abaixo é possível notar a presença dos processos cmd.exe e powershell.exe no arquivo de origem.

<h4 align="center">

 ![img](https://i.imgur.com/qTnO4iH.png)

 </h4>

* Na execução da ferramenta estão sendo inseridos os valores mimikatz.exe e vssadmin.exe via argumento "-i" 

<h4 align="center">
 
![img](https://i.imgur.com/s7wuXIn.png)

</h4>

* A ferramenta conta com um módulo de relatório que retorna uma análise de exploits disponpiveis em bases públicas como exploitDB e Packet storm. Ela sugere queries expecíficas com base nos pontos chave identificados nos exploits, a base da ferramenta que guarda as análise fica contida neste repositório, atualmente está bem pequena mas que tende a evoluir. O argumento deve obrigatoriamente ser utilizado junto a opção "--cve" ou "-cve", pois ela irá se basear nos valores extraidos do arquivo de origem para verificar se já existe análise na base interna da própria ferramenta de exploits das CVEs extraidas.

* Usabilidade.

<h4 align="center">

![img](https://i.imgur.com/bFGbF5w.png)

</h4>

* Relatório será gerado no mesmo diretório do projeto clonado.

<h4 align="center">
 
![img](https://i.imgur.com/4kD0BJI.png)

![img](https://i.imgur.com/0sOMNz5.png)

</h4>



