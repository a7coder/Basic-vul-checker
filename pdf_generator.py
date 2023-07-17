import fitz
import datetime
import sqlite3
import PyPDF2
import os

def duplicate_and_append_page(input_path, page_number, copies):
    doc = fitz.open(f"{input_path}")
    words_to_replace = ['# n', '% finding_name %',
                        'INFO', '%vul_url%', '%description%']
    page = doc[4]
    for word in words_to_replace:
        draft = page.search_for(word)
        annot = page.add_redact_annot(draft[0])
        page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE)
    doc.save("report.pdf", deflate=True)
    with open('report.pdf', 'rb') as file:
        reader = PyPDF2.PdfFileReader(file)
        writer = PyPDF2.PdfFileWriter()
        for i in range(reader.numPages):
            page = reader.getPage(i)
            writer.addPage(page)
            if i == page_number - 1:
                for i in range(copies):
                    writer.addPage(page)
        with open('temp.pdf', 'wb') as output_file:
            writer.write(output_file)
    os.remove('report.pdf')

def get_all_findings():
    conn = sqlite3.connect("db.sqlite3")
    cur = conn.cursor()
    cur.execute(
        "SELECT id,title,severity,vulnerable_url,description FROM scanner_api_finding")
    findings = cur.fetchall()
    conn.close()
    return findings

def getTime():
    res = ''
    report_time = datetime.datetime.now()
    day = report_time.day
    month = report_time.strftime("%B")
    year = report_time.year
    hour = report_time.hour
    min = report_time.minute
    return (str(day) + '/' + month + '/' + str(year) + ', ' + str(hour)+':'+str(min))

def edit_pdf(file_name, data):
    doc = fitz.open(f"{file_name}")
    website_info = {'target_url': 'www.test.com', 'target_name': 'Test'}
    page_no = [0, 0, 0]
    points = [(97, 692), (152, 692), (60, 760)]
    colors_li = [(0, 0, 0), (0, 0, 0), (0, 0, 0)]
    font_size_li = [8, 8, 8]
    words_to_replace = ["% target_name %", "% target_url %", '{%time.now%}']
    new_words = [website_info['target_name'],
                 website_info['target_url'], getTime()]
    for i in range(len(page_no)):
        page = doc[page_no[i]]
        draft = page.search_for(words_to_replace[i])
        for rect in draft:
            annot = page.add_redact_annot(rect)
            page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE)
        page.insert_text(points[i], new_words[i],
                         fontsize=font_size_li[i], color=colors_li[i])
    start_page = 4
    words_to_replace = ['# n', '% finding_name %',
                        'INFO', '%vul_url%', '%description%']
    points = [(55, 132), (100, 132), (520, 132), (132, 220), (118, 253)]
    colors = {'high': (0.9803921568627451, 0.6901960784313725, 0.6901960784313725), 'medium': (0.9803921568627451, 0.8901960784313725, 0.6823529411764706), 'low': (
        0.6549019607843137, 0.8274509803921568, 0.9372549019607843), 'info': (0, 0.6901960784313725, 0.3137254901960784)}
    k = 0
    for i in range(start_page, start_page+len(data)):
        page = doc[i]
        for j in range(len(points)):
            if j==0 or j==1:
                page.insert_text(points[j], str(data[k][j]),
                                fontsize=12, color=(0, 0, 0))
            elif j==2:
                page.draw_rect([502.14013671875, 112.54596710205078, 562.0721435546875, 142.69284057617188],color=colors[f'{data[k][j].lower()}'],fill=colors[f'{data[k][j].lower()}'])
                if data[k][j].lower()!='medium':
                    page.insert_text(points[j],str(data[k][j]),fontsize=12,color=(0,0,0))
                else:
                    page.insert_text((points[j][0]-12,points[j][1]),str(data[k][j]),fontsize=12,color=(0,0,0))
            elif j==3:
                page.insert_text(points[j], str(data[k][j]),color=(0, 0, 0),fontsize=10)                
            elif j==4:
                page.insert_textbox(fitz.Rect(33, 267, 560, 580), str(data[k][j]),
                                fontsize=11, color=(0, 0, 0), fontname='helv')
        k += 1
    doc.save("report.pdf", deflate=True)

def main():
    data = get_all_findings()
    copies = len(data)
    duplicate_and_append_page('test.pdf', 5, copies-1)
    edit_pdf('temp.pdf', data)
    os.remove('temp.pdf')

main()