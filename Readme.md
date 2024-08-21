<h1 align="center" >Watching Killer</h1>

<h4 align="center">

 ![Imgur](https://i.imgur.com/jKYzI7U.png)

</h4>

<h1>Descrição do projeto</h1>

Essa ferramenta busca realizar automação do processo de cyber threat hunting

<h3></h3>


<h4 align="center">
  
   :construction: Projeto em construção:construction:

</h4>

<h3></h3>

<!-- Modo de uso-->


<h1>Modo de uso</h1>

* Para visualizar ajuda e verificar os parâmetros necessários ou caso execute o script sem parâmetros.

```
python.exe .\Watching_Killer.py -h

 ou 

python.exe .\Watching_Killer.py --help

```
<h4 align="center">

![img](https://i.imgur.com/31bEgAA.png)

</h4>

* A ferramenta precisa que seja repassada um parâmetro posicional que será o arquivo onde contém os IOCs, podendo ser arquivos TXT ou CSV, como abaixo uma fonte de IOCs em TXT

<h4 align="center">

![img](https://i.imgur.com/TMFtz5i.png)

</h4>

* A rodar a ferramenta com os demais argumentos se utiliza o valor de IOC que deseja extrair juntamente do template de query de siem desejado, a propria ferramenta se encarregará de extrair os valores e sugerir queries

<h4 align="center">

![img](https://i.imgur.com/E9FyQcB.png)

</h4>

O argumento de reputação utiliza o serviço de API do https://www.abuseipdb.com/ então pra utiliza-lo é necessário possuir uma chave de API, que disponibilizar até 1K checks diários, a ferramenta usa preferencialmente o arquivo .env com o valor key atribuido a váriavel **abuseipdbkey**, então na mesma raiz onde foi clonado o projeto basta criar o arquivo .env e inserir o valor dentro

<h4 align="center">

![img](https://i.imgur.com/3xwtlsg.png)

</h4>



