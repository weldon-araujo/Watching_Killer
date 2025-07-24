<h1 align="center" >Watching Killer</h1>

<h4 align="center">

 ![Imgur](https://i.imgur.com/AAoJIuV.jpg)

</h4>

<h1>Descrição do projeto</h1>

O Watching Killer é uma toolkit cuja função é automatizar o processo de cyber threat hunting. Ele possui funcionalidades como: extração de IOCs e artefatos de fontes não estruturadas, consulta de reputação de endereços IP e geração de relatórios de análise de exploits públicos. Esse conjunto de ferramentas auxilia no processo, que se baseia na metodologia <a href="https://www.betaalvereniging.nl/en/safety/tahiti/" target="_blank">TAHITI</a> (Targeted Hunting integrating Threat Intelligence)

<h3></h3>


<h4 align="center">
  
   :construction: Projeto em desenvolvimento:construction:

</h4>

<h3></h3>


<h1>Arquitetura da solução</h1>

![img](https://i.imgur.com/MQFZi7Y.png)

<!-- Modo de uso-->

<h1>Modo de uso</h1>

* Após realizar a clonagem do repositório é necessário instalar as libs externas simplesmente executando **pip install -r requirements.txt** estando a partir do diretório raiz do repositório ou repassando o caminho absoluto ou relativo até o arquivo **requirements.txt**.
* Para visualizar ajuda e verificar os parâmetros necessários execute o script principal Watching_Killer.py com argumento "-h" ou "--help".

```
python.exe .\Watching_Killer.py -h

ou 

python.exe .\Watching_Killer.py --help

```
<h4 align="center">

![img](https://i.imgur.com/gB05LGD.png)
![img](https://i.imgur.com/CFs1Vue.png)

</h4>

* A ferramenta necessita de um arquivo de entrada contendo os valores a serem extraídos, independentemente de estarem estruturados ou não. Ela oferece suporte a arquivos nos formatos TXT, CSV, JSON ou XML conforme ilustrado no exemplo abaixo.

<h4 align="center">

![img](https://i.imgur.com/oMNDY81.png)

</h4>

* Como demonstrado no exemplo abaixo com o argumento "--ip", a usabilidade é a mesma para os demais argumentos --md5, --sha1, --sha256, --domain, --cve, --email, --registry e --artifact 

<h4 align="center">

![img](https://i.imgur.com/JU5l5qs.png)

</h4>
 
 * Muitas vezes, é necessário trabalhar com grandes quantidades de dados. Alguns SIEMs podem limitar a quantidade de valores por consulta. O argumento "-l" ou "--l" permite dividir os valores em duas consultas, como no exemplo abaixo.

<h4 align="center">
 
![img](https://i.imgur.com/jspJxVV.png)


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
 
![img](https://i.imgur.com/NBUfEkc.png)

</h4>

* As vezes é possível que o usuário identifique algum valor que não seja necessário nas queries, neste caso ele pode remover através do argumento --remove ou -r, o argumento é utilizável com os argumentos --ip, --domain, --email, --registry e --artifact.

<h4 align="center">
 
![img](https://i.imgur.com/enfOXeJ.png)

</h4>

* O argumento --exploitdb utilizado em conjunto com o --cve realiza uma busca por exploits públicos mantidos pela base do <a href="https://gitlab.com/exploit-database/exploitdb/" target="_blank">Exploitdb</a> no Gitlab público oficial.

<h4 align="center">
 
![img](https://i.imgur.com/WAnMNE4.png)

</h4>

* O argumento --cve_details utilizado em conjunto com o --cve traz informações acerca das CVEs extraidas.

<h4 align="center">
 
![img](https://i.imgur.com/YcuvNtA.png)

</h4>

* A ferramenta conta com um módulo de relatório que retorna uma análise de exploits disponíveis em bases públicas, como Exploit-DB e Packet Storm. Ela sugere queries específicas com base nos pontos-chave identificados nos exploits. A base de dados da ferramenta, que armazena as análises, está contida neste repositório. Atualmente, ainda é pequena, mas tende a evoluir.

* O argumento deve obrigatoriamente ser utilizado junto à opção "--cve" ou "-cve", pois a análise se baseia nos valores extraídos do arquivo de origem para verificar se já existe um registro na base interna da ferramenta sobre as CVEs identificadas.

* Usabilidade.

<h4 align="center">

![img](https://i.imgur.com/ZnamUh3.png)

</h4>

* Relatório será gerado no mesmo diretório do projeto clonado.

<h4 align="center">
 
![img](https://i.imgur.com/4kD0BJI.png)

![img](https://i.imgur.com/0sOMNz5.png)

</h4>



