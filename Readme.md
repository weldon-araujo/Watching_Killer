<h1 align="center" >Watching Killer</h1>

<h4 align="center">

 ![Imgur](https://i.imgur.com/jKYzI7U.png)

</h4>

<h1>Descrição do projeto</h1>

Essa ferramenta busca realizar automação do processo de cyber threat hunting, através de parsing de IOCs e artefatos que costumam ser utilizados em investigações de cyber threat hunting construção automática de queries específicas para investigações. 

<h3></h3>


<h4 align="center">
  
   :construction: Projeto em desenvolvimento:construction:

</h4>

<h3></h3>

<!-- Modo de uso-->


<h1>Modo de uso</h1>

* Primeiro é necessário instalar as libs externas simplesmente executando **pip install -r requirements.txt** estando no diretório raiz do reposítório ou repassando o caminho absoluto até o arquivo **requirements.txt** Para visualizar ajuda e verificar os parâmetros necessários, ou se caso execute o script principal Watching_Killer.py sem parâmetros.

```
python.exe .\Watching_Killer.py -h

ou 

python.exe .\Watching_Killer.py --help

```
<h4 align="center">

![img](https://i.imgur.com/31bEgAA.png)

</h4>

* A ferramenta precisa que seja repassada um parâmetro posicional que será o arquivo que contém os IOCs, podendo ser arquivos TXT ou CSV, como no exemplo abaixo uma fonte de IOCs em TXT.

<h4 align="center">

![img](https://i.imgur.com/TMFtz5i.png)

</h4>

* Ao rodar a ferramenta com os demais argumentos, se utiliza o valor de IOC que deseja extrair juntamente do template de query do siem desejado, a propria ferramenta se encarregará de extrair os valores e sugerir queries.

<h4 align="center">

![img](https://i.imgur.com/E9FyQcB.png)

</h4>

* O argumento de reputação utiliza o serviço de API do https://docs.abuseipdb.com/#introduction portanto pra uso desse argumento é necessário possuir uma chave de API desse serviço, que disponibiliza até 1K checks diários na categoria free, a ferramenta usa preferencialmente o arquivo .env com o valor key atribuido a váriavel **abuseipdbkey**, então na mesma raiz onde foi clonado o projeto basta criar o arquivo .env e inserir o valor dentro.

<h4 align="center">

![img](https://i.imgur.com/Z5q8k6y.png)

</h4>

* Após essa inserção a ferramenta estará apta a realização de consulta de reputação dos endereços IPs extraidos da fonte de IOCs.

<h4 align="center">

![img](https://i.imgur.com/3xwtlsg.png)

</h4>



