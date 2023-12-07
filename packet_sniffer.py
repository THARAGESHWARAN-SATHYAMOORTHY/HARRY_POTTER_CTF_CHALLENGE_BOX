#192.168.56.1


import tkinter  as tk
from tkinter import ttk
import scapy.all as scapy
import threading
import collections

def start_button():
    print('Start button clicked')
    global should_we_stop
    global thread
    global subdomain
    subdomain=subdomain_entry.get()

    if(thread is None) or (not thread.is_alive()):
        should_we_stop=False
        thread=threading.Thread(target=sniffing)
        thread.start()

def stop_button():
    global should_we_stop
    should_we_stop=True

def sniffing():
    scapy.sniff(prn=find_ips,stop_filter=stop_sniffing)

def stop_sniffing(packet):
    global should_we_stop
    return should_we_stop

def find_ips(packet):
    global scr_ip_dict
    global treev
    global subdomain

    print(packet.show())

    if 'IP' in packet:
        src_ip =packet['IP'].src
        dst_ip =packet['IP'].src

        if src_ip[0:len(subdomain)] == subdomain:
            if src_ip not in scr_ip_dict:
                scr_ip_dict[src_ip].append(dst_ip)

                row =treev.insert('',index=tk.END,text=src_ip)
                treev.insert(row,tk.END,text=dst_ip)
                treev.pack(fill=tk.X)

        else:
            if dst_ip not in scr_ip_dict[src_ip]:
                scr_ip_dict[src_ip].append(dst_ip)

                cur_item=treev.focus()
                if(treev.item(cur_item)['text']== src_ip):
                    treev.insert(cur_item,tk.END,text=dst_ip)

thread = None
should_we_stop=True
subdomain=''

scr_ip_dict= collections.defaultdict(list)

root=tk.Tk()
root.geometry('500x500')
root.title('NW Packet Analyzer')
tk.Label(root,text='NW Packet Analyzer',font='Helvetika 24 bold').pack()
tk.Label(root,text ='Enter IP Subdomain :',font='Helvetika 16 bold').pack()
subdomain_entry=tk.Entry(root)
subdomain_entry.pack(ipady=5,ipadx=50,pady=10)

treev=ttk.Treeview(root, height=400)
treev.column('#0')

button_frame =tk.Frame(root)

tk.Button(button_frame,text='Start Sniffing',command=start_button,width=15,font='Helvetika 16 bold').pack(side=tk.LEFT)
tk.Button(button_frame,text='Stop Sniffing',command=stop_button,width=15,font='Helvetika 16 bold').pack(side=tk.LEFT)

button_frame.pack(side=tk.BOTTOM,pady=10)

root.mainloop()