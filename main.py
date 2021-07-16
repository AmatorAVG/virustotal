# import time
# import xlrd
import argparse
# import itertools
import logging
import json
from vtapi3 import VirusTotalAPIUrls, VirusTotalAPIError
# , RenderTree
import requests


def r_print(*args, **kwargs):
    if not hasattr(r_print, '_state'):  # инициализация значения
        r_print._state = ""
    together = ''.join(map(str, args))  # avoid the arg is not str
    if args:
        r_print._state += together + '\n'
    else:
        r_print._state += '\n'
    if not r_print._gui:
        print(*args, **kwargs)


def main(arg):

    if arg:
        args = argparse.Namespace(**arg)
        # args.var = int(args.var)
        # args.obj = int(args.obj)
        # args.greed = int(args.greed)
    else:
        parser = argparse.ArgumentParser(description='Программа анализа вредоносности ресурсов')
        parser.add_argument('--path', help='Путь к файлу со списком URL', default='URL.txt')
        parser.add_argument('--vtkey', help='virustotal API key', default='171f17576cb1926938882625cd97519bc40d47c9dab8fa842c869b7132bd9394')
        # parser.add_argument('--vtpass', help='virustotal login')

        args = parser.parse_args()

        logging.debug(args.path)

        # api_url = 'https://www.virustotal.com/vtapi/v2/url/scan'
        # params = dict(apikey=args.vtkey, url='https://xakep.ru/author/drobotun/')
        # response = requests.post(api_url, data=params)
        # if response.status_code == 200:
        #     result = response.json()
        #     print(json.dumps(result, sort_keys=False, indent=4))

        api_url = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = dict(apikey=args.vtkey, resource='ngs.ru', scan=0)
        response = requests.get(api_url, params=params)
        if response.status_code == 200:
            result = response.json()
            print(json.dumps(result, sort_keys=False, indent=4))

        # vt_files = VirusTotalAPIUrls(args.vtkey)
        # try:
        #     result = vt_files.upload('ngs.ru')
        # except VirusTotalAPIError as err:
        #     print(err, err.err_code)
        # else:
        #     if vt_files.get_last_http_error() == vt_files.HTTP_OK:
        #         result = json.loads(result)
        #
        #         url_id_analyse = result['data']['id']
        #         result = json.dumps(result, sort_keys=False, indent=4)
        #         # logging.debug(result)
        #
        #         url_id = vt_files.get_url_id_base64('ngs.ru')
        #         result_report = vt_files.get_report(url_id)
        #         result = json.loads(result_report)
        #         result = json.dumps(result, sort_keys=False, indent=4)
        #         # logging.debug(result)
        #
        #         # result_analyse = vt_files.analyse(url_id_analyse)
        #         # result = json.loads(result_analyse)
        #         # result = json.dumps(result, sort_keys=False, indent=4)
        #         # logging.debug(result)
        #
        #         TEST_URL_ID = url_id_analyse
        #         api_url = 'https://www.virustotal.com/api/v3//analyses/' + TEST_URL_ID
        #         headers = {'x-apikey': args.vtkey}
        #         response = requests.get(api_url, headers=headers)
        #         result = json.loads(response.content)
        #         logging.debug(result)
        #
        #
        #     else:
        #         print('HTTP Error [' + str(vt_files.get_last_http_error()) +']')






if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main(False)