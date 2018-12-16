import asyncio
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from getpass import getpass
from os.path import exists

import click
import requests


def log_print(*objects, sep=' ', end='\n', file=sys.stdout, flush=False):
    if objects:
        print(time.strftime('[%d.%m.%Y - %H:%M:%S]'), *objects, sep=sep, end=end, file=file, flush=flush)


def check_proxies(threads: int, proxies: list, ping_domain: str):
    # Принимает прокси в формате http(s)/socks5:ip:port:login:pass
    # Возвращает рабочие в том-же списке
    requests_proxies = []
    for idx, line in enumerate(proxies.copy()):
        proxy_params = line.split(':')
        if len(proxy_params) < 3:
            log_print('Строка {}. Неправильный синтаксис.'.format(idx + 1))
            proxies.remove(line)
            continue
        if not proxy_params[0] in ('http', 'https', 'socks5'):
            log_print('Строка {}. Неправильный синтаксис.'.format(idx + 1))
            proxies.remove(line)
            continue
        if len(proxy_params) >= 5:
            requests_proxies.append('{}://{}:{}@{}:{}'.format(proxy_params[0], proxy_params[3], proxy_params[4], proxy_params[1], proxy_params[2]))
        else:
            requests_proxies.append('{}://{}:{}'.format(proxy_params[0], proxy_params[1], proxy_params[2]))
    with ThreadPoolExecutor(max_workers=threads) as pool:
        loop = asyncio.get_event_loop()
        futures = [loop.run_in_executor(pool, _proxy_is_worked, proxy, ping_domain) for proxy in requests_proxies]
        result = loop.run_until_complete(asyncio.gather(*futures))
    for idx, proxy in enumerate(proxies.copy()):
        if not result[idx]:
            proxies.remove(proxy)


def _proxy_is_worked(proxy: str, ping_domain: str) -> bool:
    try:
        response = requests.get(ping_domain, proxies={'http': proxy, 'https': proxy}, timeout=10)
        if response.status_code not in (requests.codes.ok, requests.codes.no_content, requests.codes.created):
            return False
        return True
    except Exception as e:
        del e
        return False


@click.command()
@click.option('--threads', '-t', default=1000, show_default=True, help='Количество потоков')
@click.option('--repeats', '-r', default=1, show_default=True, help='Количество прогонов')
@click.option('--input_file', '-i', default='unchecked_proxies.txt', show_default=True, help='Входной файл')
@click.option('--output_file', '-o', default='checked_proxies.txt', show_default=True, help='Выходной файл')
@click.option('--ping_domain', '-p', default='https://www.google.com/gen_204', show_default=True, help='Домен для проверки')
def run_proxies_checker(threads: int, repeats: int, input_file: str, output_file: str, ping_domain: str):
    """Многопоточный чекер прокси"""
    if not exists(input_file):
        log_print('Файл "{}" не найден!'.format(input_file))
        return
    if repeats < 0:
        log_print('Количество прогонов не может быть отрицательным!')
        return
    with open(input_file) as fp:
        proxies_list = []
        for line in fp:
            valuable_line = line.rstrip()
            if valuable_line:
                proxies_list.append(valuable_line)
    proxies_list = list(set(proxies_list))  # Удаляем повторяющиеся строки
    log_print('Обнаружено {} строк. Запуск проверки прокси.'.format(len(proxies_list)))
    for repeat in range(repeats):
        log_print('Старт прогона №{}'.format(repeat + 1))
        check_proxies(threads, proxies_list, ping_domain)
        log_print('Прогон №{} окончен! Найдено {} рабочих прокси!'.format(repeat + 1, len(proxies_list)))
        time.sleep(5)
    with open(output_file, 'w') as fp:
        for proxy in proxies_list:
            fp.write('{}\n'.format(proxy))


def main():
    run_proxies_checker()
    getpass('Нажмите Enter, чтобы завершить программу.')


if __name__ == '__main__':
    main()
