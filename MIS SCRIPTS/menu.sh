#CABECERA  
clear 
echo "-------------------------------------"
echo "  SISTEMA DE DEFENSA CONTRA SPOOFING  "
echo "-------------------------------------"
date
echo "autor: Iñigo Montánchez Crespo"
# MENU
sudo echo -e "sudo/root permission: \e[32mOkay\e[0m"
PS3='POR FAVOR INSERTE LA OPCION DESEADA: '  
option=("INSTALACIÓN" "DEFENSA IP" "DEFENSA ARP" "SALIR")
select opt in "${option[@]}"  
do  
    case $opt in
 	"INSTALACIÓN")
        echo "INSTALACIÓN DE DEPENDENCIAS"	
	sudo echo -e "sudo/root permission: \e[32mOkay\e[0m"
	cd INSTALACION
	sudo chmod 777 paquetes.sh
        sudo gnome-terminal -x bash -c "./paquetes.sh" &
	PID_IP=$!
	cd ..
	sudo echo -ne '\nSE PROCEDERÁ A INSTALAR LOS PAQUETES REQUERIDOS...\n\n'
        ;;

        "DEFENSA IP")
        echo "IP"	
	sudo echo -e "sudo/root permission: \e[32mOkay\e[0m"
	cd IP
	sudo chmod 777 DefensaSpoofIP.py
        sudo gnome-terminal -x bash -c "python DefensaSpoofIP.py" &
	PID_IP=$!
	cd ..
	sudo echo -ne '\nSE HA ARRANCADO EL SCRIPT DE DEFENSA IP SPOOFING.\n\n'
        ;;
        "DEFENSA ARP")
        echo "ARP"
	cd ARP
	sudo chmod 777 DefensaSpoofARP.py
	sudo echo -e "sudo/root permission: \e[32mOkay\e[0m"
        sudo gnome-terminal -x bash -c "python DefensaSpoofARP.py" &
	PID_IP=$!
	cd ..
	sudo echo -ne '\nSE HA ARRANCADO EL SCRIPT DE DEFENSA ARP SPOOFING.\n\n'
        ;;
        "SALIR")  
	break 
        ;;
        *) echo OPCION ERRONEA;;
        esac
done  
