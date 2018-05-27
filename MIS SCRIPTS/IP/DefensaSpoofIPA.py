#!/usr/bin/env python
# --*-- coding: UTF-8 --*--


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
# EJECUCIÓN DE COMANDOS EN PARALELO (TUBERIAS)
from subprocess import Popen, PIPE
# SE IMPORTA NMAP
import nmap
# PERMITE RECONOCER EXPRESIONES REGULARES
import re


#DICCIONARIO PYTHON DE ALMACENAJE DE DIRECCIONES DE LOS EQUIPOS
diccionario = dict() 
#USAMOS NMAP PARA GUARDAR LOS EQUIPOS CONECTADOS AL HOST 
nm = nmap.PortScanner() 
nm.scan(hosts = '192.168.0.1/24', arguments = '-PE -sP -n -T5')
#CAPTURAMOS LOS PAQUETES CON PCAP DE WIRESHARK CREANDO UN ARCHIVO TEMPORAL
#ADJUNTAMOS LOS PAQUETES EN EL MISMO ARCHIVO A TRAVES DE APPEND Y SYNC
try:
	pkts = PcapWriter("paquetes.pcap", append=True, sync=True)
#PARA GUARDAR EL MOMENTO DEL POSIBLE ATAQUE 
	fecha_hora = time.strftime("%c")

except:
	pass

# FUNCION IMPRIMIR HOSTS
def AnalisisRed():
	print'\nEQUIPOS DE LA RED'
#RECORREMOS TODOS LOS HOST ANTERIORMENTE GUARDADOS 
	for host in nm.all_hosts():
#SI EL HOST ESTA EN ESTADO ACTIVO 
		if nm[host]['status']['state'] != "down":

			print "\tESTADO DEL HOST:", nm[host]['status']['state']
			print "\n\tIP DEL HOST:", host

		try:
			print "\tMAC DEL HOST:", nm[host]['addresses']['mac']
		except:
			print "MAC DESCONOCIDA"
	print'\nPAQUETES'

def returnGateway():
#OBTENER LA PUERTA DE ENLACE A TRAVES DE EXPRESION REGUALR
# FUENTE 
# https://www.lawebdelprogramador.com/codigo/Python/v4490-Obtener-la-puerta-de-enlace-o-gateway-de-nuestro-Linux.html
	try:
# GUARDAMOS LA IP DEL ROUTER CAPTURANDOLA CON commands.getoutput
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


def AnalisisMac(mac_atacante):
# ARRAY DONDE SE GUARDARAN LAS IP DE LOS POSIBLES ATACANTES
	ips_atacantes = list()
	try:
# SE CREA UN FICHERO LLAMADO LOG EN EL QUE SE ESCRIBIRÁ EL TEXTO 
		fichero = open('LOG - '+fecha_hora+'.txt','w')
		fichero.write("\n\tSE HA DETECTADO UN ATAQUE DE IP SPOOFING")
	except:
		pass
# SE IMPRIMEN LOS HOSTS ATACANTES POR PANTALLA Y SE ESCRIBEN EN EL FICHERO
	for host in nm.all_hosts():
		if 'mac' in nm[host]['addresses']:
			if (nm[host]['addresses']['mac'] == mac_atacante.upper()):
				print "\n\tDatos almacenados del atacante: "
				print  "\tIP:", host
				print "\tSTATUS:", nm[host]['status']['state']
				print "\tMAC:", nm[host]['addresses']['mac']
				fichero.write("\n\n\tDATOS DE ATAQUE ALMACENADOS: \n")
				fichero.write("\n\tIP:\t\t"+ host)
				fichero.write("\n\tMAC:\t"+ nm[host]['addresses']['mac'])
				ips_atacantes.append(host)
				fichero.close()
				Bloqueo(mac_atacante.upper(), ips_atacantes)


def Bloqueo(mac_atacante, ips_atacantes):
# FUENTES
# http://www.hackplayers.com/2016/02/filtrado-de-macs-con-iptables-linux.html
# https://stackoverflow.com/questions/46705647/python-to-remove-iptables-rule-at-specific-time
	try:

		print "\n\tBloqueando conexiones entrantes de la MAC {0} ...".format(mac_atacante)
		os.system('iptables -A INPUT -i ens33 -m mac --mac-source '+ mac_atacante +' -j DROP')

		for ip_atacante in ips_atacantes:
			print "\tBloqueando conexiones entrantes de la IP {0} ...".format(ip_atacante)
			os.system('iptables -A INPUT -s '+ ip_atacante +' -j DROP')

			print "\tBloqueando conexiones salientes hacia la IP {0} ...".format(ip_atacante)
			os.system('iptables -A OUTPUT -s '+ ip_atacante +' -j DROP')

			print "\tBloqueando cualquier paquete TCP que no se ha iniciado con el Flag SYN activo..."
			os.system('iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP')

			print "\nSe han aplicado reglas para bloquear al atacante.\n"

			pause()
	except:
		print "ERROR:", sys.exc_info()[0]
		raise


def PingRouter():
# ENVIO DE PAQUETES ICMP A ROUTER PARA RECIBIR REPLY ALMACENANDO IPs Y MACs DE LOS HOST.
# USAMOS LA PUERTA DE ENLACE DST-DESTINO SRC-ORIGEN
# https://stackoverflow.com/questions/34773795/getting-source-ip-of-packet-using-scapy
	pingr = IP(dst=returnGateway())/ICMP()
	print "\n-HACIENDO PING ICMP A ROUTER-\t"
	send(pingr)

# 
def PaquetesRouter(pkt):
	ip_router = returnGateway()
	mac_router = None
	ip_pkt = pkt[IP].src
	mac_pkt = (pkt.src).upper()

# # obtengo la mac del router
	for host in nm.all_hosts():
		if 'mac' in nm[host]['addresses']:
			if host == ip_router:
				mac_router = nm[host]['addresses']['mac']
	if ip_pkt == ip_router and mac_pkt == mac_router:
	        return True
	
	elif ip_pkt != ip_router and mac_pkt == mac_router:
	        return True
	
	elif ip_pkt != ip_router and mac_pkt != mac_router:
	        return False

# PARA CADA HOST 
# FUENTE
# https://github.com/johanlundberg/python-nmap/blob/master/nmap/example.py
def Ataque(ip_dicc, mac_dicc, ip_pkt, mac_pkt):
# PARA CADA HOST HAREMOS UNA COMPARATIVA DE LAS MAC ALMACENADAS Y DE LAS IP ALMACENADAS 
	for host in nm.all_hosts():
		if 'mac' in nm[host]['addresses']:
			if nm[host]['addresses']['mac'] == mac_pkt.upper() and nm[host]['addresses']['mac'] == mac_dicc.upper():
				if ip_pkt == ip_dicc and  host != ip_dicc:
					return True
					return False
# SI LA IP DEL HOST ES DIFERENTE DE LA IP ALMACENADA PERO LA IP DE LOS PAQUETES SI QUE COINCIDE ES ATAQUE

def AnalisisPaquetes(pkt):
# AÑADIMOS PAQUETES A ARCHIVO PCAP
	pkts.write(pkt)
	PingRouter()
# VERIFICA SI EXISTE CAPA TCP EN EL LOS PAQUETES
# https://stackoverflow.com/questions/22093971/how-to-verify-if-a-packet-in-scapy-has-a-tcp-layer
	if pkt.haslayer(TCP):

 		if (pkt[IP].src in diccionario) and PaquetesRouter(pkt) == False:
#SI LA IP ESTA ALMACENADA Y NO ES UN PAQUETE DEL ROUTER 

 			for key,val in diccionario.items():
# PARA CADA VALOR DEL DICCIONARIO

 				if val == pkt.src:
# IMPRIMIR LOS VALORES 
 					print "\tIP ALMACENADA: ",format(key), "\n\tIP PAQUETE: ",format(pkt[IP].src)

 					print "\n\tMAC ALMACENADA: ", format(val)
# SI LA FUNCION ATAQUE DETECTA UNO
 					if Ataque(key, val, pkt[IP].src, pkt.src):
 						print '\n\nSE HA DETECTADO UN ATAQUE DE IP SPOOFING'
 						AnalisisMac(pkt.src)
 						return None
# SI NO DETECTA ATAQUE 					
 					else:
 						return "PAQUETE TCP RECIBIDO, NO SE HA DETECTADO ATAQUE IP SPOOFING."
 		else:
#ALMACENAR DATOS DE NUEVO EN DICCIONARIO
			diccionario[pkt[IP].src] = pkt.src
			print "\n\tIP:", format(pkt[IP].src)
			return "PAQUETE TCP RECIBIDO. DATOS DE RED ALMACENADOS."

# FUNCION PRINCIPAL
if __name__ == '__main__':
	try:
		print 'DEFENSA A ATAQUES IP SPOOFING '
# SE LLAMA A LA FUNCION ANALISIS DE LA RED
		AnalisisRed()
		while 1:
# FUENTE
# https://thepacketgeek.com/scapy-sniffing-with-custom-actions-part-1/
# https://stackoverflow.com/questions/28292224/scapy-packet-sniffer-triggering-an-action-up-on-each-sniffed-packet
# SCAPY TIENE UNA FUNCIÓN SNIFFER PARA LA  OBTENCIÓN DE PAQUETES
# PRN ENVIA LOS PAQUETES TCP DEL PUERTO 80 A LA FUNCIÓN ANALISIS SIN HACER ALMACENAJE DE ESTOS.
			sniff(prn=AnalisisPaquetes, filter="tcp port 80", store=0)

	except KeyboardInterrupt:
		sys.exit()

	except:
		print "ERROR:", sys.exc_info()[0]
		raise


			

