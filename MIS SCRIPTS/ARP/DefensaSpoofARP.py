#!/usr/bin/env python
# --*-- coding: UTF-8 --*--


__author__ = "Iñigo Montánchez Crespo"
__version__ = "1.0"
__email__ = "mci.m89@gmail.com"
__status__ = "Finished"

__author__ = "Iñigo Montánchez Crespo"
__version__ = "1.0"
__email__ = "mci.m89@gmail.com"
__status__ = "Finished"

# LOGGING PROPORCIONA UN CONJUNTO DE FUNCIONES PARA EL REGISTRO DE EVENTOS 
# (INFO, DEBUG, ERROR, WARNING ...)
import logging
#EVITA MENSAJES DE ERROR DE TIPO WARNING IPV6
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# SE IMPORTA SCAPY
from scapy.all import *
# PERMITE RECONOCER COMANDOS DE UNIX
import commands
# FUNCIONES DE TERMINAL O INTERPRETE
import sys
# SE IMPORTAN FUNCIONALIDADES DEL SISTEMA OPERATIVO
import os
# SE IMPORTAN FUNCIONES PARA TRABAJAR CON FECHA Y HORA
import time
# EJECUCIÓN DE COMANDOS EN PARALELO (TUBERÍAS)
from subprocess import Popen, PIPE
# SE IMPORTAN NMAP
import nmap
# PERMITE RECONOCER EXPRESIONES REGULARES
import re

#DICCIONARIO PYTHON DE ALMACENAJE DE DIRECCIONES DE LOS EQUIPOS
diccionario = dict() 
#USAMOS NMAP PARA GUARDAR LOS EQUIPOS CONECTADOS AL HOST 
nm = nmap.PortScanner() 
nm.scan(hosts = '192.168.0.1/24', arguments = '-n -sP -PE -T5')
#CAPTURAMOS LOS PAQUETES CON PCAP DE WIRESHARK CREANDO UN ARCHIVO TEMPORAL
#ADJUNTAMOS LOS PAQUETES EN EL MISMO ARCHIVO A TRAVES DE APPEND Y SYNC
try:
    pkts = PcapWriter("temp.pcap", append=True, sync=True)
#PARA GUARDAR EL MOMENTO DEL POSIBLE ATAQUE 
    fecha_hora = time.strftime("%c")
except:
    pass

# FUNCION PARA MOSTRAR LOS HOST DE LA RED

def AnalisisRed():
    print'\nEQUIPOS DE LA RED'
#RECORREMOS TODOS LOS HOST ANTERIORMENTE GUARDADOS 
    for host in nm.all_hosts():
#SI EL HOST ESTÁ EN ESTADO ACTIVO 
        if nm[host]['status']['state'] != "down":
            print "\tESTADO DEL HOST:", nm[host]['status']['state']
            print "\n\tIP DEL HOST:", host
            try:
                print "\tMAC DEL HOST:", nm[host]['addresses']['mac']
            except:
                print "MAC DESCONOCIDA"
    print'\nPAQUETES'



def returnGateway():
#OBTENER LA PUERTA DE ENLACE A TRAVÉS DE EXPRESIÓN REGUALR
# FUENTE 
# https://www.lawebdelprogramador.com/codigo/Python/v4490-Obtener-la-puerta-de-enlace-o-gateway-de-nuestro-Linux.html
    result = ""
    try:
        result = commands.getoutput("/sbin/route -n").splitlines()
    except:
        raise

    for line in result:
        if line.split()[0]=="0.0.0.0":
            if re.match("^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$", line.split()[1]):
                return line.split()[1]

    return ''

# FUENTE 
# https://stackoverflow.com/questions/11552320/correct-way-to-pause-python-program
def pause():
    programPause = input("PULSAR 'ENTER' PARA CONTINUAR.")

def Fichero(mac_atacante):
#SE CREA UN FICHERO DONDE SE GUARDAN LOS DATOS DEL ATACANTE
    ip_atacante = ""
    ip_router = returnGateway()
    mac_router = ""

    try:
        log = open('LOG_'+fecha_hora+'.txt','w')
        log.write("\n\tSE HA DETECTADO UN ATAQUE ARP SPOOFING")
    except:
        pass


    for host in nm.all_hosts():

        if 'mac' in nm[host]['addresses']:
            if (nm[host]['addresses']['mac'] == mac_atacante):

                print "\n\tDATOS DEL ATACANTE: "
                print "\tIP:", host
                print "\tSTATUS:", nm[host]['status']['state']
                print "\tMAC:", nm[host]['addresses']['mac']

                log.write("\n\n\tDATOS DE ATAQUE ALMACENADOS: \n")
                log.write("\n\tIP:\t\t"+ host)
                log.write("\n\tSTATUS:\t"+ nm[host]['status']['state'])
                log.write("\n\tMAC:\t"+ nm[host]['addresses']['mac'])

                ip_atacante = host

            elif(nm[host]['addresses']['ipv4'] == ip_router):
                mac_router = nm[host]['addresses']['mac']
    log.close()
    Bloqueo(ip_atacante, mac_atacante, ip_router, mac_router)



def Bloqueo(ip_atacante, mac_atacante, ip_router, mac_router):
# FUENTES
# http://www.hackplayers.com/2016/02/filtrado-de-macs-con-iptables-linux.html
# https://stackoverflow.com/questions/46705647/python-to-remove-iptables-rule-at-specific-time
    try:
        print "\n[+]\tSaneando cache ARP..."
        os.system("ip -s -s neigh flush all")
        os.system("arp -s "+ ip_router + " " + mac_router)
        print "\n[+]\tMostrando cache ARP"
        os.system("arp -a")

        print "\n\tBLOQUEANDO CONEXIÓN DE LA MAC : {0} ...".format(mac_atacante)
        os.system('iptables -A INPUT -i ens33 -m mac --mac-source '+ mac_atacante +' -j DROP')

        print "\tBLOQUEANDO CONEXION  DE LA IP : {0} ...".format(ip_atacante)
        os.system('iptables -A INPUT -s '+ ip_atacante +' -j DROP')
        os.system('iptables -A OUTPUT -s '+ ip_atacante +' -j DROP')

        print "\tBLOQUEO DE PAQUETES TCP."
        os.system('iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP')

        print "\nATAQUE BLOQUEADO CON EXITO.\n"

        pause()

    except:
        print "ERROR:", sys.exc_info()[0]
        raise



def PingRouter():
# ENVIO DE PAQUETES ICMP A ROUTER PARA RECIBIR REPLY ALMACENANDO IPs Y MACs DE LOS HOST.
# USAMOS LA PUERTA DE ENLACE DST-DESTINO SRC-ORIGEN
# https://stackoverflow.com/questions/34773795/getting-source-ip-of-packet-using-scapy
    pingr = IP(dst="192.168.0.1")/ICMP()
    print "\n-HACIENDO PING ICMP A ROUTER-\t"
    send(pingr)


def AnalisisPaquetes(pkt):
# AÑADIMOS PAQUETES A ARCHIVO PCAP
    pkts.write(pkt)
    PingRouter()
# VERIFICA SI ES UN PAQUETE ARP
# FUENTE
# https://github.com/secdev/scapy/blob/master/doc/scapy/extending.rst
# https://thepacketgeek.com/scapy-p-07-monitoring-arp/
# pkt[ARP].op == 1:  # who-has (request) 
# pkt[ARP].op == 2:  # is-at (response)
    if ARP in pkt and pkt[ARP].op in (1,2):

#SI LA IP ESTA ALMACENADA 
        if pkt[ARP].psrc in diccionario:
# IMPRIMIR LOS VALORES 
            print "\n\tIP ALMACENADA: ", format(pkt[ARP].psrc)
            print "\tMAC ALMACENADA: ",format(diccionario[pkt[ARP].psrc]), "\n\t HOST MAC: ",format(pkt[ARP].hwsrc)
# COMPARACIÓN DE LAS MACS 
# EN LAS PRUEBAS LA MAC DEL ROUTER ES :  e0:60:66:5e:dd:ea 
# MIENTRAS QUE LA DEL ATACANTE ES     :  00:0c:29:a6:b1:9a
            if diccionario[pkt[ARP].psrc] != pkt[ARP].hwsrc:
                 print '\n\nSE HA DETECTADO UN ATAQUE DE ARP SPOOFING'
                 Fichero((pkt[ARP].hwsrc).upper())
                 return None

            else:
                return "PAQUETE ARP RECIBIDO, NO SE HA DETECTADO ATAQUE ARP SPOOFING."

        else:

            #almacena la ip y la mac del origen del paquete, el PC que envia el paquete
            diccionario[pkt[ARP].psrc] = pkt[ARP].hwsrc
            print "\n\tIP:", format(pkt[ARP].psrc)
            return "PAQUETE ARP RECIBIDO. DATOS DE RED ALMACENADOS."


# FUNCION PRINCIPAL
if __name__ == '__main__':
    try:
        print 'DEFENSA A ATAQUES ARP SPOOFING '
# SE LLAMA A LA FUNCION ANALISIS DE LA RED        
        AnalisisRed()
        while 1:
# FUENTE
# https://thepacketgeek.com/scapy-sniffing-with-custom-actions-part-1/
# https://stackoverflow.com/questions/28292224/scapy-packet-sniffer-triggering-an-action-up-on-each-sniffed-packet
# SCAPY TIENE UNA FUNCIÓN SNIFFER PARA LA  OBTENCIÓN DE PAQUETES
# PRN ENVIA LOS PAQUETES TCP DEL PUERTO 80 A LA FUNCIÓN ANALISIS SIN HACER ALMACENAJE DE ESTOS.
            sniff(prn=AnalisisPaquetes, filter="arp", store=0)

    except KeyboardInterrupt:
        sys.exit()

    except:
        print "ERROR:", sys.exc_info()[0]
        raise
