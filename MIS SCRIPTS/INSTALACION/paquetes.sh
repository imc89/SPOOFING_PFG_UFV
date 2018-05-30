#!/bin/bash
clear 
echo "---------------------------"
echo "  INSTALADOR DE PAQUETES  "
echo "---------------------------"
date
echo "autor: Iñigo Montánchez Crespo"


apt-get update
apt-get install python python-nmap python-scapy
apt-get upgrade

exit 0
