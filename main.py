import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import socket
from tkinter import simpledialog
import pexpect
import yaml
import os

#Génération de la clè SSH

def generate_ssh_key():
    username = entry_username.get()
    if not username.strip():
        messagebox.showerror("Erreur", "Veuillez entrer un nom d'utilisateur pour générer la clé SSH.")
    else:
        key_filename = f"{username}_ansible_key"
        if os.path.exists(key_filename):
            messagebox.showinfo("Information", f"La clé SSH pour l'utilisateur {username} existe déjà.")
            return

        output.insert(tk.END, "Génération de la clé SSH...\n")
        try:
            ssh_keygen_cmd = f"ssh-keygen -t rsa -b 4096 -C '{username}' -f {key_filename} -N ''"
            process = subprocess.Popen(ssh_keygen_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            if stderr:
                output.insert(tk.END, f"Erreur lors de la génération de la clé SSH:\n{stderr.decode()}\n", "red")
            else:
                output.insert(tk.END, f"Clé SSH générée avec succès pour l'utilisateur {username}.\n", "green")
        except Exception as e:
            output.insert(tk.END, f"Erreur lors de la génération de la clé SSH: {str(e)}\n", "red")

#Côpy de la clé SSH vers la destation

def is_host_accessible(host, port):
    try:
        socket.setdefaulttimeout(3)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port,))
        return True
    except socket.error:
        return False
        
def ask_password():
    password = simpledialog.askstring("Mot de passe", "Entrez le mot de passe pour SSH:", show='*')
    return password

def copy_ssh_key():
    dest_host = entry_dest_host.get()
    if not dest_host.strip():
        messagebox.showerror("Erreur", "Veuillez entrer dest_host.")
    else:
        output.insert(tk.END, "##################_##################..\n", "white")
        output.insert(tk.END, "Copie de la clé SSH vers la destination pour Ansible...\n", "white")
        output.insert(tk.END, "##################_##################..\n", "white")
        if not is_host_accessible(dest_host, 22):
            messagebox.showerror("Erreur", f"L'hôte {dest_host} n'est pas accessible.")
            return

        try:
            username = entry_username.get()
            ssh_copy_cmd = f"ssh-copy-id -i {username}_ansible_key.pub {username}@{dest_host}"
            
            child = pexpect.spawn(ssh_copy_cmd)
            while True:
                index = child.expect(['password:', 'already exist', pexpect.EOF, pexpect.TIMEOUT, 'Are you sure you want to continue connecting'])
                
                if index == 0:
                    password = ask_password()
                    if not password:
                        output.insert(tk.END, "Saisie du mot de passe annulée.\n")
                        return
                    child.sendline(password)
                elif index == 1:
                    messagebox.showinfo("Information", "La clé existe déjà sur le système distant.")
                    return
                elif index == 2:
                    child.expect(pexpect.EOF)
                    output.insert(tk.END, f"Clé SSH copiée avec succès vers {dest_host} pour l'utilisateur {username}.\n", "green")
                    break  # Sortir de la boucle une fois que tout est terminé
                elif index == 3:
                    error_output = child.before.decode('utf-8')
                    output.insert(tk.END, f"Erreur lors de la copie de la clé SSH: TIMEOUT - {error_output}\n", "red")
                    break  # Sortir de la boucle en cas de timeout
                elif index == 4:
                    child.sendline('yes')  # Répondre automatiquement 'yes' à la demande de confirmation SSH
                
        except pexpect.ExceptionPexpect as e:
            output.insert(tk.END, f"Erreur lors de la copie de la clé SSH: {str(e)}\n", "red")


# Ajout des host dans inventory

def add_to_inventory(username, host_address, ssh_private_key):
    inventory_file = "/home/oliver/Documents/ansible_dir/ansible/00_inventory.yml"

    try:
        with open(inventory_file, 'r') as file:
            inventory_data = yaml.safe_load(file)
            if inventory_data is None:
                inventory_data = {"all": {"vars": {}, "hosts": {}}}

            if host_address in inventory_data["all"]["hosts"]:
                if inventory_data["all"]["hosts"][host_address]["ansible_user"] == username:
                    output.insert(tk.END, f"Utilisateur {username} existe déjà pour l'hôte {host_address}\n", "blue")
                    return

            inventory_data["all"]["hosts"][host_address] = {
                "ansible_host": host_address,
                "ansible_user": username,
                "ansible_ssh_private_key_file": ssh_private_key  # Ajout de la spécification de la clé SSH
            }

        with open(inventory_file, 'w') as file:
            yaml.dump(inventory_data, file)

        output.insert(tk.END, f"Utilisateur {username} ajouté à l'inventaire pour l'hôte {host_address}\n", "green")

    except Exception as e:
        output.insert(tk.END, f"Erreur lors de l'ajout de l'utilisateur à l'inventaire : {str(e)}\n", "red")

def on_add_user_clicked():
    # Récupérer les informations nécessaires depuis les entrées utilisateur
    username = entry_username.get()
    host_address = entry_dest_host.get()
    ssh_private_key = entry_ssh_private_key.get()  # Chemin de votre clé privée à spécifier ici

    if not username.strip() or not host_address.strip() or not ssh_private_key.strip():
        messagebox.showerror("Erreur", "Veuillez entrer un nom d'utilisateur et l'hôte destinataire pour charger dans l'inventaire.")
    else:
        add_to_inventory(username, host_address, ssh_private_key)

def remove_to_inventory(username, host_address, ssh_private_key):
    inventory_file = "/home/oliver/Documents/ansible_dir/ansible/00_inventory.yml"
    try:
        # Chargez l'inventaire YAML existant
        with open(inventory_file, 'r') as file:
            inventory_data = yaml.safe_load(file)
            if inventory_data is None:
                inventory_data = {"all": {"vars": {}, "hosts": {}}}

            # Vérifie si l'hôte est déjà dans l'inventaire
            if host_address in inventory_data["all"]["hosts"]:
                if inventory_data["all"]["hosts"][host_address]["ansible_user"] == username:
                    del inventory_data["all"]["hosts"][host_address]  # Supprime l'hôte
                    with open(inventory_file, 'w') as write_file:  # Écriture du fichier d'inventaire mis à jour au format YAML
                        yaml.dump(inventory_data, write_file)
                    output.insert(tk.END, f"Utilisateur {username} est supprimé de l'inventaire pour l'hôte {host_address}\n", "green")
                    return
                else:
                    output.insert(tk.END, f"L'utilisateur {username} n'est pas associé à l'hôte {host_address}\n", "red")
            else:
                output.insert(tk.END, f"L'hôte {host_address} n'existe pas dans l'inventaire\n", "red")

    except Exception as e:
        output.insert(tk.END, f"Erreur lors de la suppression de l'inventaire : {str(e)}\n", "red")

def on_remove_user_clicked():
    # Récupérer les informations nécessaires depuis les entrées utilisateur
    username = entry_username.get()
    host_address = entry_dest_host.get()  # Supposons que vous avez un champ pour entrer l'adresse IP
    ssh_private_key = entry_ssh_private_key.get()
    if not username.strip() and not host_address.strip():
        messagebox.showerror("Erreur", "Veuillez entrer un nom d'utilisateur et l'hôtes dest pour la charger dans l'inventory.")
    else:
      # Appel de la fonction pour la suppression l'utilisateur à l'inventaire
      remove_to_inventory(username, host_address, ssh_private_key)

# Fonction pour modifier les cibles dans le playbook YAML

def host_exists_in_playbook(playbook_path, host):
    try:
        with open(playbook_path, 'r') as file:
            playbook_content = yaml.safe_load(file)
            for play in playbook_content:
                if 'hosts' in play and host in play['hosts']:
                    return True
    except Exception as e:
        print(f"Erreur lors de la lecture du playbook : {str(e)}")
    return False

def modifier_cibles(playbook_path, nouvelle_cible):
    try:
        if host_exists_in_playbook(playbook_path, nouvelle_cible):
            output.insert(tk.END, f"L'hôte '{nouvelle_cible}' existe déjà dans le playbook.\n", "red")
            return
        
        with open(playbook_path, 'r') as file:
            playbook = yaml.safe_load(file)

            # Modifier l'adresse hôte dans le playbook
            playbook[0]['hosts'] = nouvelle_cible

        with open(playbook_path, 'w') as file:
            yaml.dump(playbook, file)
        
        output.insert(tk.END, f"Adresse hôte modifiée avec succès : {nouvelle_cible}\n", "green")
    except Exception as e:
        output.insert(tk.END, f"Erreur lors de la modification de l'adresse hôte : {str(e)}\n", "red")

def on_click_modifier():
    playbook = "/home/oliver/Documents/ansible_dir/ansible/playbook.yml"
    nouvelle_cible = entry_cible.get()  
    if not nouvelle_cible.strip():
        messagebox.showerror("Erreur", "Veuillez entrer l'adresse de l'hôte.")
    else:
       # Modifier les cibles dans le playbook YAML
       modifier_cibles(playbook, nouvelle_cible)

#Recherche des rôles existant 

def role_exists_in_playbook(playbook_path, role_name):
    try:
        with open(playbook_path, 'r') as file:
            playbook_content = yaml.safe_load(file)
            for play in playbook_content:
                if 'roles' in play:
                    for role in play['roles']:
                        if 'role' in role and role['role'] == role_name:
                            return True
    except Exception as e:
        print(f"Erreur lors de la lecture du playbook : {str(e)}")
    return False

#Execute Ansible
def ask_sudo_password():
    password = simpledialog.askstring("Mot de passe", "Entrez le mot de passe pour BECOME:", show='*')
    return password

def run_ansible():
    inventory = "/home/oliver/Documents/ansible_dir/ansible/00_inventory.yml"
    playbook = "/home/oliver/Documents/ansible_dir/ansible/playbook.yml"
    role = entry_role.get()
#    roles = f"/home/oliver/Documents/ansible_dir/roles/{role}"
    
    if not role_exists_in_playbook(playbook, role):
      output.insert(tk.END, f"Le rôle '{role}' n'existe pas dans le playbook.\n", "red")
      return

    try:
        command = f"ansible-playbook -i {inventory} {playbook} -K --tags {role}"

        child = pexpect.spawn(command, timeout=600)
        index = child.expect(['password:', pexpect.EOF, pexpect.TIMEOUT])
        
        if index == 0:
            password = ask_sudo_password()
            if not password:
                output.insert(tk.END, "Saisie du mot de passe annulée.\n")
                return

            child.sendline(password)
            index = child.expect([pexpect.EOF, pexpect.TIMEOUT])

        if index == 0:
            output_text = child.before.decode()
            formatted_output = format_ansible_output(output_text)
            output.insert(tk.END, "Ansible a terminé avec succès:\n", "green")
            output.insert(tk.END, formatted_output, "green")
        elif index == 1:
            output.insert(tk.END, "Erreur lors de l'exécution d'Ansible: End of File.\n", "red")
        elif index == 2:
            output.insert(tk.END, "Erreur lors de l'exécution d'Ansible: Timeout exceeded.\n", "red")

    except Exception as e:
        output.insert(tk.END, f"Erreur lors de l'exécution d'Ansible: {str(e)}\n", "red")
    
def format_ansible_output(output_text):
    # Supprimer les balises de couleur ANSI pour une meilleure lisibilité
    formatted_output = remove_ansi_color(output_text)
    return formatted_output

def remove_ansi_color(text):
    # Fonction pour supprimer les balises de couleur ANSI de la sortie
    import re
    ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)

# Fonction pour dessiner les onglets avec des couleurs personnalisées

def style_notebook():
    style = ttk.Style()
    style.theme_create("custom", parent="alt", settings={
        "TNotebook": {"configure": {"tabmargins": [2, 5, 2, 0]}},
        "TNotebook.Tab": {
            "configure": {"padding": [5, 1], "background": "lightblue", "foreground": "blue"},
            "map": {"background": [("selected", "lightblue")],
                    "foreground": [("selected", "blue")],
                    "expand": [("selected", [1, 1, 1, 0])]}}})
    style.theme_use("custom")

def clear_output():
    output.delete(1.0, tk.END)

#Interface utilisateur Tk

root = tk.Tk()
root.title("Interface Ansible")

root.configure(bg="white")

notebook = ttk.Notebook(root)
notebook.pack(padx=50, pady=50, fill='both', expand=True)

# Onglet "Clés SSH"

frame_ssh = ttk.Frame(notebook)
notebook.add(frame_ssh, text='Clés SSH')

label_username = tk.Label(frame_ssh, text="Nom d'utilisateur:")
label_username.pack()
entry_username = tk.Entry(frame_ssh)
entry_username.pack()

button_generate_key = tk.Button(frame_ssh, text="Générer clé SSH", command=generate_ssh_key, bg="blue", fg="white")
button_generate_key.pack()

label_dest_host = tk.Label(frame_ssh, text="Destination de la clé SSH pour Ansible:")
label_dest_host.pack()
entry_dest_host = tk.Entry(frame_ssh)
entry_dest_host.pack()

label_ssh_private_key = tk.Label(frame_ssh, text="Chemin clé privé:")
label_ssh_private_key.pack()

entry_ssh_private_key= tk.Entry(frame_ssh)
entry_ssh_private_key.pack()

button_copy_key = tk.Button(frame_ssh, text="Copier clé SSH", command=copy_ssh_key, bg="green", fg="white")
button_copy_key.pack()

button_run_ansible = tk.Button(frame_ssh, text="Add Inventory", command=on_add_user_clicked, bg="orange", fg="black")
button_run_ansible.pack()

button_run_ansible = tk.Button(frame_ssh, text="Delete Inventory", command=on_remove_user_clicked, bg="red", fg="black")
button_run_ansible.pack()

# Onglet "Exécution Ansible"

frame_ansible = ttk.Frame(notebook)
notebook.add(frame_ansible, text='Exécution Ansible')

label_cible = tk.Label(frame_ansible, text="Nouvelle adresse hôte:")
label_cible.pack()

entry_cible = tk.Entry(frame_ansible)
entry_cible.pack()

# Création du bouton "Modifier"
bouton_modifier = tk.Button(frame_ansible, text="Modifier", command=on_click_modifier, bg="green", fg="black")
bouton_modifier.pack()

label_role = tk.Label(frame_ansible, text="Rôle Ansible à exécuter:")
label_role.pack()
entry_role = tk.Entry(frame_ansible)
entry_role.pack()

button_run_ansible = tk.Button(frame_ansible, text="Exécuter Ansible", command=run_ansible, bg="orange", fg="black")
button_run_ansible.pack()

#sortie ddans la zone de texte

scrollbar = tk.Scrollbar(root)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

output = tk.Text(root, height=100, width=100, yscrollcommand=scrollbar.set)
output.pack()

scrollbar.config(command=output.yview)

output.tag_configure("red", foreground="red")
output.tag_configure("green", foreground="green")
output.tag_configure("white", foreground="white")
output.tag_configure("blue", foreground="blue")
output.configure(bg="black")

# Appliquer le style personnalisé aux onglets du Notebook
style_notebook()

# Créer un bouton pour effacer le contenu de la zone de texte
button_clear = tk.Button(root, text="Clear", command=clear_output, bg="#8B0000", fg="black")
button_clear.pack()
button_clear.lift()

root.mainloop()
