from fpdf import FPDF

class CVEReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'Watching Killer Exploit Analysis', 0, 1, 'C')
        self.ln(10)
    
    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Página {self.page_no()}', 0, 0, 'C')

def generator_report(cve_id, descricao, queries, imagens):
    pdf = CVEReport()
    pdf.add_page()
    
    # Título da CVE
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, f'CVE Analisada: {cve_id}', ln=True)
    pdf.ln(10)
    
    # Descrição
    pdf.set_font('Arial', '', 12)
    pdf.multi_cell(0, 10, f'Descrição: {descricao}')
    pdf.ln(5)
    
    # Sugestões de Queries
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'Sugestões de Queries para Hunting:', ln=True)
    pdf.set_font('Arial', '', 12)
    for query in queries:
        pdf.multi_cell(0, 10, f'- {query}')
        pdf.ln(2)
    pdf.ln(10)
    
    # Inserir imagens
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'Capturas de Tela:', ln=True)
    for img_path in imagens:
        pdf.image(img_path, x=10, y=None, w=180)
        pdf.ln(10)
    
    # Gerar PDF
    file_name = f"relatorio_{cve_id.replace(':', '_')}.pdf"
    pdf.output(file_name)
    print(f"Relatório gerado: {file_name}")

# Exemplo de uso
cve_id = "CVE-2022_41040"
descricao = "Vulnerabilidade de elevação de privilégio do Microsoft Exchange Server"
queries = [
    "IBM QRADAR",
    '''SELECT * FROM events 
    WHERE URL LIKE '%/mapi/nspi%'
      OR URL LIKE '%/Autodiscover/autodiscover.json%' 
      AND http_status_code IN (401, 200)
      GROUP BY "HTTP Method", http_status_code, URL
      START '2024-01-01 00:00:00' STOP '2024-01-07 00:00:00'''
]
imagens = ["go.png"]

generator_report(cve_id, descricao, queries, imagens)
