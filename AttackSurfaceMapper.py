#!/usr/bin/env -S sudo python3
"""
Проверка порта TCP с использованием Scapy
"""
#Подключение дополнительных библиотек
import os
import sys
import traceback
import g4f
from enum import IntEnum
from pathlib import Path
from random import randint
from typing import Dict, List
from argparse import ArgumentParser
from scapy.layers.inet import IP, TCP, ICMP
from scapy.packet import Packet
from scapy.sendrecv import sr1, sr

NON_PRIVILEGED_LOW_PORT = 1025
NON_PRIVILEGED_HIGH_PORT = 65534
ICMP_DESTINATION_UNREACHABLE = 3

#Класс для ответов на TCP-запросы
class TcpFlags(IntEnum):
    """
    CWR | ECE | URG | ACK | PSH | RST | SYN | FIN
     0     0     0     1     0     0     1     0  -> SYN + ACT
     
    CWR | ECE | URG | ACK | PSH | RST | SYN | FIN
     0     0     0     0     1     1     0     0  -> RST + PSH
    """
    #Соединение установлено
    SYNC_ACK = 0x12
    #Соединение сброшено
    RST_PSH = 0x14

#Класс для ответов на ICMP-запросы
class IcmpCodes(IntEnum):
    """
    Коды ICMP:
    0	Net is unreachable
    1	Host is unreachable
    2	Protocol is unreachable
    3	Port is unreachable
    4	Fragmentation is needed and Don't Fragment was set
    5	Source route failed
    6	Destination network is unknown
    7	Destination host is unknown
    8	Source host is isolated
    9	Communication with destination network is administratively prohibited
    10	Communication with destination host is administratively prohibited
    11	Destination network is unreachable for type of service
    12	Destination host is unreachable for type of service
    13	Communication is administratively prohibited
    14	Host precedence violation
    15	Precedence cutoff is in effect
    """
    Host_is_unreachable = 1
    Protocol_is_unreachable = 2
    Port_is_unreachable = 3
    Communication_with_destination_network_is_administratively_prohibited = 9
    Communication_with_destination_host_is_administratively_prohibited = 10
    Communication_is_administratively_prohibited = 13


FILTERED_CODES = [x.value for x in IcmpCodes]

#Класс для ответов
class RESPONSES(IntEnum):
    """
    Индивидуальные ответы на проверку наших портов
    """
    #Фильтровано файерволом
    FILTERED = 0
    #Закрыто
    CLOSED = 1
    #Открыто
    OPEN = 2
    #Ошибка
    ERROR = 3

#Функция для загрузки списка сетевых ресурсов
def load_machines_port(the_data_file: Path) -> Dict[str, List[int]]:
    """
    Парсинг csv-файла
    """
    port_data = {}
    with open(the_data_file, 'r', encoding="utf-8") as d_scan:
        for line in d_scan:
            host, ports = line.split(';')
            port_data[host] = [int(p) for p in ports.split(',')]
    return port_data

#Функция для попытки установки TCP-соединения с сетевым ресурсом
def test_port(
        address: str,
        dest_ports: int,
        verbose: bool = False
) -> RESPONSES:
    """
    Проверка комбинации адрес + порт
    :param address: Хост для проверки
    :param dest_ports: Порты для проверки
    :return: Ответные и неотвеченные пакеты (отфильтрованные)
    """
    src_port = randint(NON_PRIVILEGED_LOW_PORT, NON_PRIVILEGED_HIGH_PORT)
    ip = IP(dst=address)
    ports = TCP(sport=src_port, dport=dest_ports, flags="S")
    reset_tcp = TCP(sport=src_port, dport=dest_ports, flags="S")
    packet: Packet = ip / ports
    verb_level = 0
    if verbose:
        verb_level = 99
        packet.show()
    try:
        answered = sr1(
            packet,
            verbose=verb_level,
            retry=1,
            timeout=1,
            threaded=True
        )
        if not answered:
            return RESPONSES.FILTERED
        elif answered.haslayer(TCP):
            if answered.getlayer(TCP).flags == TcpFlags.SYNC_ACK:
                rst_packet = ip / reset_tcp
                sr(rst_packet, timeout=1, verbose=verb_level)
                return RESPONSES.OPEN
            elif answered.getlayer(TCP).flags == TcpFlags.RST_PSH:
                return RESPONSES.CLOSED
        elif answered.haslayer(ICMP):
            icmp_type = answered.getlayer(ICMP).type
            icmp_code = int(answered.getlayer(ICMP).code)
            if icmp_type == ICMP_DESTINATION_UNREACHABLE and icmp_code in FILTERED_CODES:
                return RESPONSES.FILTERED
    except TypeError:
        traceback.print_exc(file=sys.stdout)
        return RESPONSES.ERROR

#Главная функция, которая принимает на вход csv-файл
if __name__ == "__main__":
    #Проверка, что скрипт запущен с правами администратора
    if os.getuid() != 0:
        raise EnvironmentError("Sorry, you need to be root to run this program!")
    #Парсинг переданных аргументов
    PARSER = ArgumentParser(description=__doc__)
    PARSER.add_argument("--verbose", action="store_true", help="Toggle verbose mode on/ off")
    PARSER.add_argument("scan_file", type=Path, help="Scan file with list of hosts and ports")
    ARGS = PARSER.parse_args()
    #ПРОМТ-запрос для GPT-чата
    promt="Написать подробный отчёт без конфиденциальных данных об результатах сканирования и найденных уязвимостях CVE и CWE, определить CMS, рассчитать CVSS:\n"
    #Загружаем список сетевых ресурсов из файла .csv
    data = load_machines_port(ARGS.scan_file)
    #Для каждого сетевого ресурса проверяем доступность
    for machine in data:
        m_ports = data[machine]
        for dest_port in m_ports:
            ans = test_port(address=machine, dest_ports=dest_port, verbose=ARGS.verbose)
            #Если ресурс доступен, то запускаем сканер nikto
            if(ans.name=="OPEN"):
                print(f"{machine}:{dest_port} -> {ans.name}")
                response = os.popen(f"nikto -h {machine} -p {dest_port}")
                nikto_output = response.readlines()
                for nikto_line in nikto_output:
                    #Добавляем вывод сканера nikto в наш ПРОМТ-запрос для GPT-чата
                    promt+=nikto_line.rstrip('\n')
                    print(nikto_line.rstrip('\n'))
            else:
                print(f"{machine}:{dest_port} -> {ans.name}")
    #Пробуем запросить отчёт у GPT-чата           
    try:
        response = g4f.ChatCompletion.create(
            model=g4f.models.gpt_4o,
            messages=[{"role": "user", "content": promt}],
            provider=g4f.Provider.Liaobots,
            stream=True,
        )
        for message in response:
            print(message, flush=True, end="")
    #Если GPT-чат недоступен, то сообщаем об этом
    except Exception as e:
        print(f"{g4f.Provider.Liaobots.__name__}:", e)
        print("Извините, произошла ошибка. ЧатGPT для создания отчёта недоступен!")
        