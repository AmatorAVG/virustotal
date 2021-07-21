import requests
from xlsxwriter.workbook import Workbook
import sqlite3
import shodan
import PySimpleGUI as sg
import pysimplesql as ss
import logging
import time
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def delete_db(path_db):
    try:
        sqlite_connection = sqlite3.connect(path_db)
        sqlite_drop_table_query = '''DELETE FROM Journal;'''
        cursor = sqlite_connection.cursor()
        logging.info("База данных подключена к SQLite")
        cursor.execute(sqlite_drop_table_query)
        sqlite_connection.commit()
        logging.info("Таблица sqlitedb_report очищена")

        cursor.close()
        if sqlite_connection:
            sqlite_connection.close()
            logging.info("Соединение с SQLite закрыто")
        return True
    except sqlite3.Error as error:
        logging.error("Ошибка при подключении к sqlite " + str(error))
        return False


def insert_multiple_records(path_db, records):
    try:
        sqlite_connection = sqlite3.connect(path_db)
        cursor = sqlite_connection.cursor()
        logging.info("Подключен к SQLite")

        sqlite_insert_query = """INSERT or REPLACE INTO Journal
                                 (resource, vt_positives, sh_vulnerabilities, sh_ports, sh_services)
                                 VALUES (?, ?, ?, ?, ?);"""

        cursor.executemany(sqlite_insert_query, records)
        sqlite_connection.commit()
        logging.info("%s записи успешно вставлены в таблицу Journal", cursor.rowcount)
        sqlite_connection.commit()
        cursor.close()

    except sqlite3.Error as error:
        logging.error("Ошибка при работе с SQLite " + str(error))
    finally:
        if sqlite_connection:
            sqlite_connection.close()
            logging.info("Соединение с SQLite закрыто")


def is_url(sUrl):
    if not sUrl:
        return False
    import re
    # this method is used by Django
    regex = re.compile(
        r'(^https?://)?'  # http:// or https:// or ""
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return bool(regex.search(sUrl))


def get_data_from_sites(path, vtkey, shkey, timer):

    api_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    records_to_insert = []
    with open(path) as fi:
        use_timer = False
        for line in fi:
            if use_timer:
                print(f'Пауза {timer} секунд...')
                time.sleep(timer)
            else:
                use_timer = True

            sUrl = line.rstrip()
            if not is_url(sUrl):
                print(sUrl, ' не является URL или IP!')
                continue
            print("Обрабатываем адрес: ", sUrl + "...")
            # shodan
            try:
                # Setup the api
                api = shodan.Shodan(shkey)

                # Perform the search
                result = api.search(sUrl)

                # Loop through the matches and print each IP
                ip_set = set()
                for service in result['matches']:
                    ip_set.add((service['ip_str']))
                    break  # Анализируем только один IP-адрес, так как их для домена может быть изрядное количество
                ipinfo = dict()
                services = ''
                for ip in ip_set:
                    ipinfo = api.host(ip)
                    data_set = set(x.get('product', "") for x in ipinfo['data'] if not x.get('product', "") == "")
                    services = ', '.join(data_set)

            except Exception as e:
                print('Error: %s' % e)
                return

            # virustotal
            params = dict(apikey=vtkey, resource=sUrl, scan=0)
            response = requests.get(api_url, params=params)
            logging.info(response.status_code)
            if response.status_code == 200:
                result = response.json()
                logging.info(result)
                to_append = (sUrl, str(result.get('positives', 0)),
                             ', '.join(ipinfo.get('vulns', [])),
                             ', '.join(str(x) for x in ipinfo.get('ports', [])),
                             services)
                records_to_insert.append(to_append)
            elif response.status_code == 204:
                print('Превышено допустимое число обращений к серверу virustotal. Повторите через минуту.')
                if records_to_insert:
                    insert_multiple_records('sqlite.db', records_to_insert)
                return



    if records_to_insert:
        insert_multiple_records('sqlite.db', records_to_insert)


def export_to_excel(path):
    workbook = Workbook(path)
    worksheet = workbook.add_worksheet()
    conn = sqlite3.connect('sqlite.db')
    c = conn.cursor()
    mysel = c.execute("select * from Journal")
    for i, row in enumerate(mysel):
        for j, value in enumerate(row):
            worksheet.write(i, j, value)
    workbook.close()
    print("Данные успешно экспортированы в файл ", path)


# -------------------------------------
# CREATE A DATABASE TO WORK WITH
# -------------------------------------
sql = """
CREATE TABLE Journal(
    "id" INTEGER NOT NULL PRIMARY KEY,
    "resource" TEXT,
    "vt_positives" TEXT,
    "sh_vulnerabilities" TEXT,
    "sh_ports" TEXT,
    "sh_services" TEXT
);
"""

# -------------------------
# CREATE PYSIMPLEGUI LAYOUT
# -------------------------
# Define the columns for the table selector
headings = ['id', 'Ресурс         ', 'Вредоносность (VT)', 'Уязвимости (SH)     ',
            'Порты (SH)            ', 'Службы (SH)         ']
visible = [0, 1, 1, 1, 1, 1]
layout = [
    [sg.Text('Путь к текстовому файлу со списком URL:', size=(35, 1), auto_size_text=False, justification='left'),
        sg.InputText('URL.txt', size=(74, 1)), sg.FileBrowse(file_types=(("Text files", ".txt"),))],
    [sg.Text('Virustotal API key:', size=(14, 1), auto_size_text=False, justification='left'),
        sg.InputText('171f17576cb1926938882625cd97519bc40d47c9dab8fa842c869b7132bd9394', size=(65, 1))],
    [sg.Text('Shodan API key:', size=(14, 1), auto_size_text=False, justification='left'),
        sg.InputText('mWeGtOq6iKA4tdKdQ5Py1mpczHdwYZui', size=(65, 1))],
    [sg.Text('Путь к файлу Excel:', size=(35, 1), auto_size_text=False, justification='left'),
     sg.InputText('export.xlsx', size=(74, 1)), sg.FileBrowse(file_types=(("Excel files", "*.xlsx"),))],

    [sg.Text('Пауза между запросами, сек:', size=(25, 1), auto_size_text=False, justification='left'),
     sg.Slider(range=(0, 30), orientation='h', size=(34, 20), default_value=10, key='Timer')],
    
    [sg.Button('Обновить данные с сайтов', key=f'btnRefresh', size=(22, 1)),
     sg.Button('Экспортировать в Excel', key=f'btnExport', size=(22, 1))],

    ss.selector('sel_journal', 'Journal', sg.Table, num_rows=15, headings=headings, visible_column_map=visible),

    ss.actions('act_journal', 'Journal'),
    ss.record('Journal.resource', size=(105, 1)),
    ss.record('Journal.vt_positives', size=(3, 1)),
    ss.record('Journal.sh_vulnerabilities', size=(105, 1)),
    ss.record('Journal.sh_ports', size=(105, 1)),
    ss.record('Journal.sh_services', size=(105, 1)),
    [sg.Output(size=(122, 8), key='-OUTPUT-')],
]
layout[5][0].VerticalScrollOnly = False
win = sg.Window('Программа анализа вредоносности ресурсов', layout, finalize=True)
db = ss.Database('sqlite.db', win,  sql_commands=sql)

# Reverse the default sort order so new journal entries appear at the top
# db['Journal'].set_order_clause('ORDER BY resource DESC')
# Set the column order for search operations.
# By default, only the column designated as the description column is searched
db['Journal'].set_search_order(['resource', 'vt_positives', 'sh_vulnerabilities', 'sh_ports', 'sh_services'])

# ---------
# MAIN LOOP
# ---------
while True:
    event, values = win.read()

    if db.process_events(event, values):
        logger.info(f'PySimpleDB event handler handled the event {event}!')
    elif event == sg.WIN_CLOSED or event == 'Exit':
        db = None              # <= ensures proper closing of the sqlite database and runs a database optimization
        break
    elif event == 'btnRefresh':
        delete_db('sqlite.db')
        b = ss.Database('sqlite.db', win)
        get_data_from_sites(values[0], values[1], values[2], int(values['Timer']))
        db = ss.Database('sqlite.db', win)
        print("Обработка завершена.")
    elif event == 'btnExport':
        export_to_excel(values[3])
    else:
        logger.info(f'This event ({event}) is not yet handled.')
